from collections.abc import AsyncGenerator
import logging
from typing import Any

from fastapi import APIRouter, Depends, status
from fastapi.responses import JSONResponse, StreamingResponse

from sentinelai.proxy.exceptions import PromptSecurityBlockedError
from sentinelai.proxy.router import LLMRouter, get_router
from sentinelai.schemas.chat import (
    ChatCompletionRequest,
    ChatCompletionResponse,
)
from sentinelai.security.engine import SecurityEngine, get_security_engine

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

    # 2. Forward to target provider (streaming or non-streaming)
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
