from typing import Any
from fastapi import status
from sentinelai.exceptions import SentinelAIError


class LLMProxyError(SentinelAIError):
    """Base exception for proxy and provider errors."""

    def __init__(
        self,
        message: str,
        status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
        error_type: str = "api_error",
        code: str | None = None,
        details: Any = None,
    ):
        super().__init__(message=message, status_code=status_code, details=details)
        self.error_type = error_type
        self.code = code or "proxy_error"


class ProviderNotConfiguredError(LLMProxyError):
    """Raised when an unconfigured or missing provider is requested."""

    def __init__(self, provider: str, detail: str = ""):
        msg = f"Provider '{provider}' is not configured. {detail}".strip()
        super().__init__(
            message=msg,
            status_code=status.HTTP_400_BAD_REQUEST,
            error_type="invalid_request_error",
            code="provider_not_configured",
        )


class ProviderTimeoutError(LLMProxyError):
    """Raised when an upstream provider times out."""

    def __init__(self, provider: str, timeout_seconds: float):
        super().__init__(
            message=f"Upstream provider '{provider}' timed out after {timeout_seconds} seconds.",
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            error_type="timeout_error",
            code="gateway_timeout",
        )


class ProviderConnectionError(LLMProxyError):
    """Raised when upstream provider cannot be reached."""

    def __init__(self, provider: str, reason: str):
        super().__init__(
            message=f"Failed to connect to provider '{provider}': {reason}",
            status_code=status.HTTP_502_BAD_GATEWAY,
            error_type="api_error",
            code="bad_gateway",
        )


class UpstreamProviderError(LLMProxyError):
    """Raised when upstream provider returns an error response."""

    def __init__(self, provider: str, status_code: int, message: str):
        super().__init__(
            message=f"Provider '{provider}' error ({status_code}): {message}",
            status_code=status_code if 400 <= status_code < 599 else status.HTTP_502_BAD_GATEWAY,
            error_type="upstream_error",
            code=f"provider_error_{status_code}",
        )


class PromptSecurityBlockedError(LLMProxyError):
    """Raised when incoming prompt violates security policies (injection, jailbreak, exfiltration)."""

    def __init__(
        self,
        message: str = "Request blocked by SentinelAI Security Engine: detected prompt injection or security violation.",
        status_code: int = status.HTTP_403_FORBIDDEN,
        details: Any = None,
    ):
        super().__init__(
            message=message,
            status_code=status_code,
            error_type="security_violation",
            code="prompt_security_blocked",
            details=details,
        )


class SecretLeakDetectedError(LLMProxyError):
    """Raised when request or payload contains unmasked credentials, API keys, or secrets."""

    def __init__(
        self,
        message: str = "Request blocked: unmasked secrets, API keys, or credentials detected.",
        status_code: int = status.HTTP_403_FORBIDDEN,
        details: Any = None,
    ):
        super().__init__(
            message=message,
            status_code=status_code,
            error_type="security_violation",
            code="secret_leak_detected",
            details=details,
        )


class UnauthorizedToolError(LLMProxyError):
    """Raised when client requests unauthorized or restricted tool execution."""

    def __init__(
        self,
        message: str = "Tool call blocked: unauthorized tool or forbidden parameters.",
        status_code: int = status.HTTP_403_FORBIDDEN,
        details: Any = None,
    ):
        super().__init__(
            message=message,
            status_code=status_code,
            error_type="security_violation",
            code="unauthorized_tool_call",
            details=details,
        )


class HealthSafetyBlockedError(LLMProxyError):
    """Raised when request poses critical health, medical overdose, or life-safety hazards."""

    def __init__(
        self,
        message: str = "Request blocked due to health or life-safety policy violation.",
        status_code: int = status.HTTP_400_BAD_REQUEST,
        details: Any = None,
    ):
        super().__init__(
            message=message,
            status_code=status_code,
            error_type="health_safety_violation",
            code="health_safety_blocked",
            details=details,
        )
