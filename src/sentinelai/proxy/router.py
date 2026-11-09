from collections.abc import AsyncGenerator
import logging

from sentinelai.config import Settings, get_settings
from sentinelai.proxy.base import BaseLLMProvider
from sentinelai.proxy.exceptions import ProviderNotConfiguredError
from sentinelai.proxy.gemini import GeminiProvider
from sentinelai.proxy.ollama import OllamaProvider
from sentinelai.schemas.chat import (
    ChatCompletionChunk,
    ChatCompletionRequest,
    ChatCompletionResponse,
)

logger = logging.getLogger("sentinelai.proxy.router")


class LLMRouter:
    """Routes incoming chat completion requests to appropriate provider adapters."""

    def __init__(self, settings: Settings | None = None):
        self.settings = settings or get_settings()
        self.providers: dict[str, BaseLLMProvider] = {
            "ollama": OllamaProvider(
                base_url=self.settings.ollama_base_url,
                timeout_seconds=self.settings.ollama_timeout_seconds,
            ),
            "gemini": GeminiProvider(
                api_key=self.settings.gemini_api_key,
                base_url=self.settings.gemini_base_url,
                timeout_seconds=self.settings.gemini_timeout_seconds,
            ),
        }

    def resolve_provider(self, requested_model: str) -> tuple[BaseLLMProvider, str]:
        """Determine target provider adapter and underlying model name."""
        model_lower = requested_model.lower()

        if model_lower.startswith("ollama/"):
            provider_key = "ollama"
            actual_model = requested_model[len("ollama/") :]
        elif model_lower.startswith("gemini/"):
            provider_key = "gemini"
            actual_model = requested_model[len("gemini/") :]
        elif model_lower.startswith("gemini-"):
            provider_key = "gemini"
            actual_model = requested_model
        else:
            provider_key = self.settings.default_llm_provider.lower()
            actual_model = requested_model

        provider = self.providers.get(provider_key)
        if not provider:
            raise ProviderNotConfiguredError(
                provider=provider_key,
                detail=f"Supported providers are: {', '.join(self.providers.keys())}",
            )

        return provider, actual_model

    async def generate(self, request: ChatCompletionRequest) -> ChatCompletionResponse:
        """Route non-streaming chat completion."""
        provider, actual_model = self.resolve_provider(request.model)
        logger.info(
            "Routing request to provider: %s (model: %s)",
            provider.name,
            actual_model,
            extra={"provider": provider.name, "model": actual_model, "stream": False},
        )
        return await provider.generate(request, actual_model)

    async def stream(
        self, request: ChatCompletionRequest
    ) -> AsyncGenerator[ChatCompletionChunk, None]:
        """Route streaming chat completion."""
        provider, actual_model = self.resolve_provider(request.model)
        logger.info(
            "Routing streaming request to provider: %s (model: %s)",
            provider.name,
            actual_model,
            extra={"provider": provider.name, "model": actual_model, "stream": True},
        )
        async for chunk in provider.stream(request, actual_model):
            yield chunk


_router_instance: LLMRouter | None = None


def get_router() -> LLMRouter:
    """Dependency provider for LLMRouter singleton."""
    global _router_instance
    if _router_instance is None:
        _router_instance = LLMRouter()
    return _router_instance
