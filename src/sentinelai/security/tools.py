import re
from typing import Any
from pydantic import BaseModel, Field

from sentinelai.config import Settings, get_settings
from sentinelai.security.events import emit_security_event


class ToolAuthorizationResult(BaseModel):
    """Result of evaluating tool execution authorization."""

    is_authorized: bool
    tool_name: str
    status: str  # AUTHORIZED, UNAUTHORIZED, BLOCKED
    reason: str
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)


# Dangerous parameter injection patterns inside tool arguments
DANGEROUS_PARAM_PATTERNS = [
    re.compile(r"(?:;\s*(?:rm\b|bash\b|sh\b|curl\b|wget\b|python\b|chmod\b|nc\b))"),
    re.compile(r"(?:\b(?:cat\s+/etc/passwd|\.\./\.\./))"),
    re.compile(r"(?:\$\([^)]+\)|`[^`]+`)"),
]


class ToolAuthorizer:
    """Enforces explicit allowlists, blocklists, and parameter constraints on tool calls."""

    def __init__(self, settings: Settings | None = None):
        self.settings = settings or get_settings()
        self.allowed_tools = set(self.settings.security_allowed_tools)
        self.blocked_tools = set(self.settings.security_blocked_tools)

    def _inspect_arguments(self, arguments: dict[str, Any] | None) -> tuple[bool, str]:
        """Verify tool arguments do not contain shell injection or path traversal."""
        if not arguments:
            return True, ""

        def check_val(val: Any) -> tuple[bool, str]:
            if isinstance(val, str):
                for pat in DANGEROUS_PARAM_PATTERNS:
                    if pat.search(val):
                        return False, f"Potentially malicious parameter detected matching {pat.pattern}"
            elif isinstance(val, dict):
                for k, v in val.items():
                    ok, reason = check_val(v)
                    if not ok:
                        return False, reason
            elif isinstance(val, list):
                for item in val:
                    ok, reason = check_val(item)
                    if not ok:
                        return False, reason
            return True, ""

        return check_val(arguments)

    def authorize(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
        role: str = "user",
    ) -> ToolAuthorizationResult:
        """Authorize a single tool invocation request."""
        clean_name = tool_name.strip()

        # 1. Check explicit blocked tools
        if clean_name in self.blocked_tools:
            res = ToolAuthorizationResult(
                is_authorized=False,
                tool_name=clean_name,
                status="BLOCKED",
                reason=f"Tool '{clean_name}' is explicitly forbidden by security policy.",
                risk_score=1.0,
            )
            emit_security_event(
                event_type="unauthorized_tool_call",
                severity="CRITICAL",
                action="BLOCKED",
                risk_score=1.0,
                details={"tool_name": clean_name, "reason": res.reason},
            )
            return res

        # 2. Check explicit allowlist
        if self.allowed_tools and clean_name not in self.allowed_tools:
            res = ToolAuthorizationResult(
                is_authorized=False,
                tool_name=clean_name,
                status="UNAUTHORIZED",
                reason=f"Tool '{clean_name}' is not in the authorized tools allowlist.",
                risk_score=0.85,
            )
            emit_security_event(
                event_type="unauthorized_tool_call",
                severity="HIGH",
                action="BLOCKED",
                risk_score=0.85,
                details={"tool_name": clean_name, "reason": res.reason},
            )
            return res

        # 3. Check parameters
        is_safe_params, param_reason = self._inspect_arguments(arguments)
        if not is_safe_params:
            res = ToolAuthorizationResult(
                is_authorized=False,
                tool_name=clean_name,
                status="BLOCKED",
                reason=f"Tool arguments failed security inspection: {param_reason}",
                risk_score=0.90,
            )
            emit_security_event(
                event_type="malicious_tool_arguments",
                severity="HIGH",
                action="BLOCKED",
                risk_score=0.90,
                details={"tool_name": clean_name, "reason": param_reason},
            )
            return res

        # Authorized
        return ToolAuthorizationResult(
            is_authorized=True,
            tool_name=clean_name,
            status="AUTHORIZED",
            reason=f"Tool '{clean_name}' is authorized for execution.",
            risk_score=0.0,
        )


_authorizer_instance: ToolAuthorizer | None = None


def get_tool_authorizer() -> ToolAuthorizer:
    """Singleton dependency provider for ToolAuthorizer."""
    global _authorizer_instance
    if _authorizer_instance is None:
        _authorizer_instance = ToolAuthorizer()
    return _authorizer_instance
