from collections.abc import AsyncGenerator
import logging
from typing import Any

from fastapi import APIRouter, Depends, status
from fastapi.responses import JSONResponse, StreamingResponse

from sentinelai.proxy.exceptions import (
    PromptSecurityBlockedError,
    SecretLeakDetectedError,
    UnauthorizedToolError,
)
from sentinelai.proxy.router import LLMRouter, get_router
from sentinelai.schemas.chat import (
    ChatCompletionRequest,
    ChatCompletionResponse,
)
from sentinelai.security.engine import SecurityEngine, get_security_engine
from sentinelai.security.pii import PIIScanner
from sentinelai.security.secrets import SecretScanner
from sentinelai.security.tools import ToolAuthorizer, get_tool_authorizer

logger = logging.getLogger("sentinelai.api.chat")

router = APIRouter(prefix="/v1", tags=["Chat Completions"])


async def sse_event_stream(
    router_instance: LLMRouter, request: ChatCompletionRequest
) -> AsyncGenerator[str, None]:
    """Stream formatted Server-Sent Events for OpenAI compatibility."""
    try:
        async for chunk in router_instance.stream(request):
            yield f"data: {chunk.model_dump_json()}\n\n"
        yield "data: [DONE]\n\n"
    except Exception as exc:
        logger.exception("Error while streaming response: %s", str(exc))
        # Deliver error in SSE stream if possible before terminating
        error_payload = {
            "error": {
                "message": str(exc),
                "type": "server_error",
                "param": None,
                "code": "streaming_error",
            }
        }
        import json
        yield f"data: {json.dumps(error_payload)}\n\n"
        yield "data: [DONE]\n\n"


_chat_secret_scanner = SecretScanner()
_chat_pii_scanner = PIIScanner()


def get_chat_secret_scanner() -> SecretScanner:
    return _chat_secret_scanner


def get_chat_pii_scanner() -> PIIScanner:
    return _chat_pii_scanner


@router.post(
    "/chat/completions",
    response_model=ChatCompletionResponse,
    status_code=status.HTTP_200_OK,
    summary="OpenAI-Compatible Chat Completions",
    description="Reverse proxy for OpenAI-compatible chat requests routing to Ollama or Gemini.",
)
async def create_chat_completion(
    request: ChatCompletionRequest,
    router_instance: LLMRouter = Depends(get_router),
    security_engine: SecurityEngine = Depends(get_security_engine),
    secret_scanner: SecretScanner = Depends(get_chat_secret_scanner),
    tool_authorizer: ToolAuthorizer = Depends(get_tool_authorizer),
    pii_scanner: PIIScanner = Depends(get_chat_pii_scanner),
) -> Any:
    """Handle chat completion request in standard JSON or SSE streaming format."""
    # 1. Inspect request through Input Security Engine before provider routing
    assessment = security_engine.evaluate_messages(request.messages)
    if assessment.is_blocked:
        raise PromptSecurityBlockedError(
            message=f"Request blocked by SentinelAI Security Engine: {assessment.summary}",
            status_code=security_engine.settings.security_block_status_code,
            details=assessment.to_error_details(),
        )

    # 2. Inspect for unmasked credentials & secret leakage
    if security_engine.settings.security_block_on_secrets:
        for msg in request.messages:
            if msg.role.lower() == "user":
                detected_secrets = secret_scanner.scan(msg.get_text_content())
                if detected_secrets:
                    raise SecretLeakDetectedError(
                        message="Request blocked: unmasked secrets or credentials detected in prompt.",
                        status_code=security_engine.settings.security_block_status_code,
                        details={
                            "types": list({s.secret_type for s in detected_secrets}),
                            "count": len(detected_secrets),
                            "masked_previews": [s.masked_preview for s in detected_secrets],
                        },
                    )

    # 3. Tool Authorization Check
    if request.tools:
        for tool_def in request.tools:
            name = None
            if isinstance(tool_def, dict):
                if tool_def.get("type") == "function" and isinstance(tool_def.get("function"), dict):
                    name = tool_def["function"].get("name")
                else:
                    name = tool_def.get("name")
            if name:
                auth_res = tool_authorizer.authorize(tool_name=name)
                if not auth_res.is_authorized:
                    raise UnauthorizedToolError(
                        message=f"Tool declaration rejected: {auth_res.reason}",
                        status_code=security_engine.settings.security_block_status_code,
                        details={
                            "tool_name": name,
                            "status": auth_res.status,
                            "reason": auth_res.reason,
                        },
                    )

    # 4. Optional PII Redaction
    if security_engine.settings.security_redact_pii:
        for msg in request.messages:
            if isinstance(msg.content, str):
                redacted, _ = pii_scanner.redact(msg.content)
                msg.content = redacted

    # 5. Forward to target provider (streaming or non-streaming)
    if request.stream:
        return StreamingResponse(
            sse_event_stream(router_instance, request),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    response = await router_instance.generate(request)
    return response
