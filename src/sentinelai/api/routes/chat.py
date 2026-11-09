from collections.abc import AsyncGenerator
import logging
from typing import Any

from fastapi import APIRouter, Depends, status
from fastapi.responses import JSONResponse, StreamingResponse

from sentinelai.proxy.router import LLMRouter, get_router
from sentinelai.schemas.chat import (
    ChatCompletionRequest,
    ChatCompletionResponse,
)

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
) -> Any:
    """Handle chat completion request in standard JSON or SSE streaming format."""
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
