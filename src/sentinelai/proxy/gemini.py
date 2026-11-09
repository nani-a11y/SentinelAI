from collections.abc import AsyncGenerator
import json
import logging
from typing import Any

import httpx

from sentinelai.proxy.base import BaseLLMProvider
from sentinelai.proxy.exceptions import (
    ProviderConnectionError,
    ProviderNotConfiguredError,
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

logger = logging.getLogger("sentinelai.proxy.gemini")


class GeminiProvider(BaseLLMProvider):
    """Adapter for Google Gemini REST API."""

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str = "https://generativelanguage.googleapis.com/v1beta",
        timeout_seconds: float = 60.0,
    ):
        super().__init__(name="gemini")
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout_seconds

    def _ensure_configured(self) -> None:
        """Verify API key is present."""
        if not self.api_key or not self.api_key.strip():
            raise ProviderNotConfiguredError(
                provider=self.name,
                detail="GEMINI_API_KEY environment variable is missing or empty.",
            )

    def _build_payload(self, request: ChatCompletionRequest) -> dict[str, Any]:
        """Convert OpenAI chat messages and options to Gemini generateContent format."""
        contents: list[dict[str, Any]] = []
        system_parts: list[str] = []

        for msg in request.messages:
            text_content = msg.get_text_content()
            if msg.role == "system":
                system_parts.append(text_content)
            elif msg.role in ("assistant", "model"):
                contents.append({
                    "role": "model",
                    "parts": [{"text": text_content}],
                })
            else:
                contents.append({
                    "role": "user",
                    "parts": [{"text": text_content}],
                })

        generation_config: dict[str, Any] = {}
        if request.temperature is not None:
            generation_config["temperature"] = request.temperature
        if request.top_p is not None:
            generation_config["topP"] = request.top_p
        max_tokens = request.effective_max_tokens()
        if max_tokens is not None:
            generation_config["maxOutputTokens"] = max_tokens
        if request.stop is not None:
            generation_config["stopSequences"] = (
                [request.stop] if isinstance(request.stop, str) else request.stop
            )

        payload: dict[str, Any] = {"contents": contents}

        if system_parts:
            payload["systemInstruction"] = {
                "parts": [{"text": "\n\n".join(system_parts)}]
            }

        if generation_config:
            payload["generationConfig"] = generation_config

        return payload

    def _normalize_model_name(self, model: str) -> str:
        """Strip provider prefix if present (e.g. 'gemini/gemini-1.5-flash' -> 'gemini-1.5-flash')."""
        if model.startswith("gemini/"):
            return model[len("gemini/") :]
        return model

    async def _post(
        self, endpoint: str, payload: dict[str, Any], headers: dict[str, str]
    ) -> httpx.Response:
        """Execute HTTP POST with timeout."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                return await client.post(endpoint, json=payload, headers=headers)
        except httpx.TimeoutException as exc:
            raise ProviderTimeoutError(provider=self.name, timeout_seconds=self.timeout) from exc
        except httpx.ConnectError as exc:
            raise ProviderConnectionError(provider=self.name, reason=str(exc)) from exc
        except httpx.RequestError as exc:
            raise ProviderConnectionError(provider=self.name, reason=str(exc)) from exc

    async def generate(
        self, request: ChatCompletionRequest, actual_model: str
    ) -> ChatCompletionResponse:
        """Execute non-streaming completion against Gemini."""
        self._ensure_configured()
        normalized_model = self._normalize_model_name(actual_model)
        endpoint = f"{self.base_url}/models/{normalized_model}:generateContent"
        payload = self._build_payload(request)
        headers = {
            "Content-Type": "application/json",
            "x-goog-api-key": self.api_key,
        }

        res = await self._post(endpoint, payload, headers)

        if res.status_code >= 400:
            raise UpstreamProviderError(provider=self.name, status_code=res.status_code, message=res.text)

        data = res.json()
        candidates = data.get("candidates", [])
        if not candidates:
            content_text = ""
            finish_reason = "stop"
        else:
            first_candidate = candidates[0]
            parts = first_candidate.get("content", {}).get("parts", [])
            content_text = "".join(part.get("text", "") for part in parts)
            raw_reason = first_candidate.get("finishReason", "STOP")
            finish_reason = "stop" if raw_reason in ("STOP", None) else raw_reason.lower()

        usage_data = data.get("usageMetadata", {})
        prompt_tokens = usage_data.get("promptTokenCount", 0)
        completion_tokens = usage_data.get("candidatesTokenCount", 0)
        total_tokens = usage_data.get("totalTokenCount", prompt_tokens + completion_tokens)

        return ChatCompletionResponse(
            id=self.generate_completion_id(),
            created=self.current_timestamp(),
            model=request.model,
            choices=[
                ChatChoice(
                    index=0,
                    message=ChatChoiceMessage(role="assistant", content=content_text),
                    finish_reason=finish_reason,
                )
            ],
            usage=UsageInfo(
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=total_tokens,
            ),
        )

    async def stream(
        self, request: ChatCompletionRequest, actual_model: str
    ) -> AsyncGenerator[ChatCompletionChunk, None]:
        """Execute streaming completion against Gemini using SSE."""
        self._ensure_configured()
        normalized_model = self._normalize_model_name(actual_model)
        endpoint = f"{self.base_url}/models/{normalized_model}:streamGenerateContent?alt=sse"
        payload = self._build_payload(request)
        headers = {
            "Content-Type": "application/json",
            "x-goog-api-key": self.api_key,
        }
        completion_id = self.generate_completion_id()
        created_time = self.current_timestamp()

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                async with client.stream("POST", endpoint, json=payload, headers=headers) as response:
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
                        if not line or not line.startswith("data: "):
                            continue

                        data_str = line[len("data: ") :].strip()
                        if not data_str:
                            continue

                        try:
                            chunk_data = json.loads(data_str)
                        except json.JSONDecodeError:
                            continue

                        candidates = chunk_data.get("candidates", [])
                        if not candidates:
                            continue

                        cand = candidates[0]
                        parts = cand.get("content", {}).get("parts", [])
                        chunk_text = "".join(p.get("text", "") for p in parts)
                        raw_reason = cand.get("finishReason")
                        finish_reason = (
                            "stop" if raw_reason == "STOP" else (raw_reason.lower() if raw_reason else None)
                        )

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
