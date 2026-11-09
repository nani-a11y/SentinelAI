from typing import Any
from pydantic import BaseModel, Field


class ChatMessage(BaseModel):
    """Chat message object adhering to OpenAI specifications."""

    role: str
    content: str | list[dict[str, Any]]
    name: str | None = None

    def get_text_content(self) -> str:
        """Extract plain text representation of the message content."""
        if isinstance(self.content, str):
            return self.content
        if isinstance(self.content, list):
            parts: list[str] = []
            for item in self.content:
                if isinstance(item, dict) and item.get("type") == "text":
                    parts.append(item.get("text", ""))
                elif isinstance(item, str):
                    parts.append(item)
            return "".join(parts)
        return str(self.content)


class ChatCompletionRequest(BaseModel):
    """OpenAI-compatible chat completion request."""

    model: str
    messages: list[ChatMessage]
    temperature: float | None = Field(default=None, ge=0.0, le=2.0)
    top_p: float | None = Field(default=None, ge=0.0, le=1.0)
    n: int | None = Field(default=1, ge=1)
    stream: bool = False
    stop: str | list[str] | None = None
    max_tokens: int | None = Field(default=None, ge=1)
    max_completion_tokens: int | None = Field(default=None, ge=1)
    presence_penalty: float | None = Field(default=None, ge=-2.0, le=2.0)
    frequency_penalty: float | None = Field(default=None, ge=-2.0, le=2.0)
    user: str | None = None

    def effective_max_tokens(self) -> int | None:
        """Return either max_completion_tokens or legacy max_tokens."""
        return self.max_completion_tokens or self.max_tokens


class UsageInfo(BaseModel):
    """Token usage counters."""

    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


class ChatChoiceMessage(BaseModel):
    """Assistant message payload in completion choices."""

    role: str = "assistant"
    content: str


class ChatChoice(BaseModel):
    """Choice object in chat completion response."""

    index: int = 0
    message: ChatChoiceMessage
    finish_reason: str | None = "stop"


class ChatCompletionResponse(BaseModel):
    """OpenAI-compatible chat completion JSON response."""

    id: str
    object: str = "chat.completion"
    created: int
    model: str
    choices: list[ChatChoice]
    usage: UsageInfo | None = None


class ChatChunkDelta(BaseModel):
    """Delta update within a streaming chunk."""

    role: str | None = None
    content: str | None = None


class ChatChunkChoice(BaseModel):
    """Choice within a streaming chunk."""

    index: int = 0
    delta: ChatChunkDelta
    finish_reason: str | None = None


class ChatCompletionChunk(BaseModel):
    """OpenAI-compatible SSE chat completion chunk."""

    id: str
    object: str = "chat.completion.chunk"
    created: int
    model: str
    choices: list[ChatChunkChoice]
