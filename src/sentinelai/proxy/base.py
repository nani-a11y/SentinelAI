from abc import ABC, abstractmethod
from collections.abc import AsyncGenerator
import time
import uuid

from sentinelai.schemas.chat import (
    ChatCompletionChunk,
    ChatCompletionRequest,
    ChatCompletionResponse,
)


class BaseLLMProvider(ABC):
    """Abstract base class for LLM provider adapters."""

    def __init__(self, name: str):
        self.name = name

    def generate_completion_id(self) -> str:
        """Generate unique OpenAI-compatible completion identifier."""
        return f"chatcmpl-{uuid.uuid4().hex[:24]}"

    def current_timestamp(self) -> int:
        """Get current Unix timestamp."""
        return int(time.time())

    @abstractmethod
    async def generate(
        self, request: ChatCompletionRequest, actual_model: str
    ) -> ChatCompletionResponse:
        """Execute non-streaming completion."""
        ...

    @abstractmethod
    async def stream(
        self, request: ChatCompletionRequest, actual_model: str
    ) -> AsyncGenerator[ChatCompletionChunk, None]:
        """Execute streaming completion yielding OpenAI-compatible chunks."""
        ...
