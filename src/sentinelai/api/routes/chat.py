from collections.abc import AsyncGenerator
import json
import logging
import time
from typing import Any
import uuid

from fastapi import APIRouter, Depends, status
from fastapi.responses import JSONResponse, StreamingResponse

from sentinelai.proxy.exceptions import (
    HealthSafetyBlockedError,
    PromptSecurityBlockedError,
    SecretLeakDetectedError,
    UnauthorizedToolError,
)
from sentinelai.proxy.router import LLMRouter, get_router
from sentinelai.schemas.chat import (
    ChatChunkChoice,
    ChatChunkDelta,
    ChatCompletionChunk,
    ChatCompletionRequest,
    ChatCompletionResponse,
)
from sentinelai.security.engine import SecurityEngine, get_security_engine
from sentinelai.security.health_safety import (
    HealthSafetyEngine,
    get_health_safety_engine,
)
from sentinelai.security.output_guard import (
    OutputGuard,
    StreamingOutputSanitizer,
    get_output_guard,
)
from sentinelai.security.pii import PIIScanner
from sentinelai.security.secrets import SecretScanner
from sentinelai.security.tools import ToolAuthorizer, get_tool_authorizer

logger = logging.getLogger("sentinelai.api.chat")

router = APIRouter(prefix="/v1", tags=["Chat Completions"])


async def sse_event_stream(
    router_instance: LLMRouter,
    request: ChatCompletionRequest,
    output_guard: OutputGuard,
    health_safety_engine: HealthSafetyEngine | None = None,
    emergency_guidance: str | None = None,
) -> AsyncGenerator[str, None]:
    """Stream formatted Server-Sent Events with real-time output sanitization."""
    sanitizer = StreamingOutputSanitizer(
        output_guard=output_guard,
        health_safety_engine=health_safety_engine,
    )

    try:
        if emergency_guidance:
            init_chunk = ChatCompletionChunk(
                id=f"chatcmpl-{uuid.uuid4().hex[:12]}",
                created=int(time.time()),
                model=request.model,
                choices=[
                    ChatChunkChoice(
                        index=0,
                        delta=ChatChunkDelta(role="assistant", content=f"{emergency_guidance}\n\n"),
                        finish_reason=None,
                    )
                ],
            )
            yield f"data: {init_chunk.model_dump_json()}\n\n"

        async for chunk in router_instance.stream(request):
            delta = chunk.choices[0].delta if chunk.choices else None
            is_finish = bool(chunk.choices and chunk.choices[0].finish_reason)
            delta_content = delta.content if delta else None

            sanitized_text = sanitizer.process_chunk(delta_content, is_last=is_finish)

            if delta is not None:
                if sanitized_text is not None:
                    delta.content = sanitized_text
                if sanitized_text is not None or is_finish:
                    yield f"data: {chunk.model_dump_json()}\n\n"

            if sanitizer.blocked:
                break

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
    output_guard: OutputGuard = Depends(get_output_guard),
    health_safety_engine: HealthSafetyEngine = Depends(get_health_safety_engine),
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

    # 2. Health Safety Input Evaluation (Overdose, Intentional Harm, Emergency)
    emergency_guidance: str | None = None
    for msg in request.messages:
        if msg.role.lower() == "user":
            h_assessment = health_safety_engine.evaluate_input(msg.get_text_content())
            if h_assessment.is_blocked:
                raise HealthSafetyBlockedError(
                    message=f"Request blocked by Health Safety: {h_assessment.reason}",
                    status_code=status.HTTP_400_BAD_REQUEST,
                    details={
                        "category": h_assessment.category,
                        "emergency_guidance": h_assessment.emergency_guidance,
                        "reason": h_assessment.reason,
                    },
                )
            if h_assessment.is_emergency and h_assessment.emergency_guidance:
                emergency_guidance = h_assessment.emergency_guidance

    # 3. Inspect for unmasked credentials & secret leakage in prompt
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

    # 4. Tool Authorization Check
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

    # 5. Optional Input PII Redaction
    if security_engine.settings.security_redact_pii:
        for msg in request.messages:
            if isinstance(msg.content, str):
                redacted, _ = pii_scanner.redact(msg.content)
                msg.content = redacted

    # 6. Forward to target provider (streaming or non-streaming)
    if request.stream:
        return StreamingResponse(
            sse_event_stream(
                router_instance,
                request,
                output_guard,
                health_safety_engine=health_safety_engine,
                emergency_guidance=emergency_guidance,
            ),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    response = await router_instance.generate(request)

    # 7. Output Security Inspection & Redaction
    if response.choices and response.choices[0].message:
        raw_output = response.choices[0].message.content
        out_assessment = output_guard.inspect_and_sanitize(raw_output)
        sanitized_health_text, _ = health_safety_engine.evaluate_output(out_assessment.sanitized_text)
        if emergency_guidance and emergency_guidance not in sanitized_health_text:
            sanitized_health_text = f"{emergency_guidance}\n\n{sanitized_health_text}"
        response.choices[0].message.content = sanitized_health_text

    return response
