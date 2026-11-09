from collections.abc import AsyncGenerator
import json
import logging
from typing import Any

import httpx

from sentinelai.proxy.base import BaseLLMProvider
from sentinelai.proxy.exceptions import (
    ProviderConnectionError,
    ProviderTimeoutError,
    UpstreamProviderError,
)
from sentinelai.schemas.chat import (
    ChatChoice,
    ChatChoiceMessage,
    ChatChunkChoice,
    ChatChunkDelta,
    ChatCompletionChunk,
    ChatCompletionRequest,
    ChatCompletionResponse,
    UsageInfo,
)

logger = logging.getLogger("sentinelai.proxy.ollama")


class OllamaProvider(BaseLLMProvider):
    """Adapter for local or remote Ollama LLM service."""

    def __init__(self, base_url: str = "http://127.0.0.1:11434", timeout_seconds: float = 60.0):
        super().__init__(name="ollama")
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout_seconds

    def _build_payload(self, request: ChatCompletionRequest, actual_model: str, stream: bool) -> dict[str, Any]:
        """Convert OpenAI request to Ollama chat payload."""
        messages: list[dict[str, str]] = [
            {"role": msg.role, "content": msg.get_text_content()} for msg in request.messages
        ]

        options: dict[str, Any] = {}
        if request.temperature is not None:
            options["temperature"] = request.temperature
        if request.top_p is not None:
            options["top_p"] = request.top_p
        max_tokens = request.effective_max_tokens()
        if max_tokens is not None:
            options["num_predict"] = max_tokens
        if request.stop is not None:
            options["stop"] = [request.stop] if isinstance(request.stop, str) else request.stop
        if request.presence_penalty is not None:
            options["presence_penalty"] = request.presence_penalty
        if request.frequency_penalty is not None:
            options["frequency_penalty"] = request.frequency_penalty

        payload: dict[str, Any] = {
            "model": actual_model,
            "messages": messages,
            "stream": stream,
        }
        if options:
            payload["options"] = options
        return payload

    async def _post(self, endpoint: str, payload: dict[str, Any]) -> httpx.Response:
        """Execute HTTP POST with timeout."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                return await client.post(endpoint, json=payload)
        except httpx.TimeoutException as exc:
            raise ProviderTimeoutError(provider=self.name, timeout_seconds=self.timeout) from exc
        except httpx.ConnectError as exc:
            raise ProviderConnectionError(provider=self.name, reason=str(exc)) from exc
        except httpx.RequestError as exc:
            raise ProviderConnectionError(provider=self.name, reason=str(exc)) from exc

    async def generate(
        self, request: ChatCompletionRequest, actual_model: str
    ) -> ChatCompletionResponse:
        """Execute non-streaming completion against Ollama."""
        endpoint = f"{self.base_url}/api/chat"
        payload = self._build_payload(request, actual_model, stream=False)

        res = await self._post(endpoint, payload)

        if res.status_code >= 400:
            raise UpstreamProviderError(provider=self.name, status_code=res.status_code, message=res.text)

        data = res.json()
        message_data = data.get("message", {})
        content = message_data.get("content", "")
        role = message_data.get("role", "assistant")

        prompt_tokens = data.get("prompt_eval_count", 0)
        completion_tokens = data.get("eval_count", 0)
        finish_reason = data.get("done_reason") or "stop"

        return ChatCompletionResponse(
            id=self.generate_completion_id(),
            created=self.current_timestamp(),
            model=request.model,
            choices=[
                ChatChoice(
                    index=0,
                    message=ChatChoiceMessage(role=role, content=content),
                    finish_reason=finish_reason,
                )
            ],
            usage=UsageInfo(
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=prompt_tokens + completion_tokens,
            ),
        )

    async def stream(
        self, request: ChatCompletionRequest, actual_model: str
    ) -> AsyncGenerator[ChatCompletionChunk, None]:
        """Execute streaming completion against Ollama."""
        endpoint = f"{self.base_url}/api/chat"
        payload = self._build_payload(request, actual_model, stream=True)
        completion_id = self.generate_completion_id()
        created_time = self.current_timestamp()

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                async with client.stream("POST", endpoint, json=payload) as response:
                    if response.status_code >= 400:
                        error_body = await response.aread()
                        raise UpstreamProviderError(
                            provider=self.name,
                            status_code=response.status_code,
                            message=error_body.decode(errors="replace"),
                        )

                    is_first_chunk = True
                    async for line in response.aiter_lines():
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            chunk_data = json.loads(line)
                        except json.JSONDecodeError:
                            continue

                        delta_msg = chunk_data.get("message", {})
                        chunk_text = delta_msg.get("content", "")
                        is_done = chunk_data.get("done", False)
                        finish_reason = chunk_data.get("done_reason") or ("stop" if is_done else None)

                        delta = ChatChunkDelta(
                            role="assistant" if is_first_chunk else None,
                            content=chunk_text,
                        )
                        is_first_chunk = False

                        yield ChatCompletionChunk(
                            id=completion_id,
                            created=created_time,
                            model=request.model,
                            choices=[
                                ChatChunkChoice(
                                    index=0,
                                    delta=delta,
                                    finish_reason=finish_reason,
                                )
                            ],
                        )
        except httpx.TimeoutException as exc:
            raise ProviderTimeoutError(provider=self.name, timeout_seconds=self.timeout) from exc
        except httpx.ConnectError as exc:
            raise ProviderConnectionError(provider=self.name, reason=str(exc)) from exc
        except httpx.RequestError as exc:
            raise ProviderConnectionError(provider=self.name, reason=str(exc)) from exc
