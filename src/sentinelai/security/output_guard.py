import logging
import re
from typing import Any, NamedTuple
from pydantic import BaseModel, Field

from sentinelai.config import Settings, get_settings
from sentinelai.security.events import emit_security_event
from sentinelai.security.pii import PIIScanner
from sentinelai.security.secrets import SecretScanner

logger = logging.getLogger("sentinelai.security.output")


class OutputSecurityAssessment(BaseModel):
    """Result of scanning and sanitizing generated LLM output."""

    is_blocked: bool = False
    is_redacted: bool = False
    sanitized_text: str
    leaks_detected: list[str] = Field(default_factory=list)
    action: str = "ALLOWED"  # ALLOWED, REDACTED, BLOCKED
    reason: str = "Output passed security evaluation."


# System prompt disclosure indicators in generated output
SYSTEM_PROMPT_LEAK_PATTERNS = [
    re.compile(
        r"(?i)\b(?:here\s+is\s+(?:the|my)\s+system\s+prompt|my\s+system\s+instructions\s+are|"
        r"the\s+instructions\s+given\s+to\s+me\s+(?:were|are)|my\s+developer\s+guidelines\s+state|"
        r"system\s+prompt\s*:\s*|system\s+instructions\s*:\s*)\b"
    ),
    re.compile(
        r"(?i)(?:<<SYS>>[\s\S]*?<<\/SYS>>|<system>[\s\S]*?<\/system>|\[SYSTEM_PROMPT\][\s\S]*?\[\/SYSTEM_PROMPT\])"
    ),
]

# Unsafe generated payloads (destructive commands, fork bombs)
UNSAFE_GENERATED_PATTERNS = [
    re.compile(r"(?i)\b(?:rm\s+-rf\s+/(?:\s|\b)|:\(\)\s*\{\s*:\|:&\s*\}\s*;\s*:|dd\s+if=/dev/(?:zero|urandom)\s+of=/dev/[a-z0-9]+)\b"),
]

CRITICAL_SECRET_TYPES = {"PRIVATE_KEY", "DATABASE_CONNECTION_STRING", "OPENAI_API_KEY", "GOOGLE_GEMINI_KEY"}


class OutputGuard:
    """Scans and sanitizes LLM completions before returning them to clients."""

    def __init__(
        self,
        settings: Settings | None = None,
        secret_scanner: SecretScanner | None = None,
        pii_scanner: PIIScanner | None = None,
    ):
        self.settings = settings or get_settings()
        self.secret_scanner = secret_scanner or SecretScanner()
        self.pii_scanner = pii_scanner or PIIScanner()

    def inspect_and_sanitize(self, content: str) -> OutputSecurityAssessment:
        """Scan generated output for secrets, PII, prompt leakage, and dangerous commands."""
        if not self.settings.output_protection_enabled or not content:
            return OutputSecurityAssessment(
                is_blocked=False,
                is_redacted=False,
                sanitized_text=content,
            )

        leaks: list[str] = []
        is_blocked = False
        is_redacted = False
        current_text = content
        reason = "Output passed security evaluation."

        # 1. Check for Unsafe / Destructive Generated Payloads
        for pat in UNSAFE_GENERATED_PATTERNS:
            if pat.search(current_text):
                is_blocked = True
                leaks.append("DESTRUCTIVE_COMMAND_PAYLOAD")
                reason = "Generated content contains destructive shell payload."
                emit_security_event(
                    event_type="unsafe_output_blocked",
                    severity="CRITICAL",
                    action="BLOCKED",
                    risk_score=1.0,
                    raw_payload_for_fingerprint=content,
                    details={"reason": reason},
                )
                return OutputSecurityAssessment(
                    is_blocked=True,
                    is_redacted=False,
                    sanitized_text="[BLOCKED BY SENTINELAI: Generated response contains potentially dangerous content]",
                    leaks_detected=leaks,
                    action="BLOCKED",
                    reason=reason,
                )

        # 2. Check for System Prompt Disclosure
        if self.settings.output_detect_prompt_leakage:
            for pat in SYSTEM_PROMPT_LEAK_PATTERNS:
                if pat.search(current_text):
                    leaks.append("SYSTEM_PROMPT_DISCLOSURE")
                    # Replace system prompt leak disclosure
                    current_text = pat.sub("[SYSTEM PROMPT DISCLOSURE REDACTED BY SENTINELAI]", current_text)
                    is_redacted = True

        # 3. Check for Secrets & Credentials
        if self.settings.output_redact_secrets:
            secrets = self.secret_scanner.scan(current_text)
            if secrets:
                for s in secrets:
                    leaks.append(f"SECRET_{s.secret_type}")

                # Check if critical leak triggers full response block
                has_critical_secret = any(s.secret_type in CRITICAL_SECRET_TYPES for s in secrets)
                if has_critical_secret and self.settings.output_block_critical_leaks:
                    is_blocked = True
                    reason = "Generated response contains critical credential or private key leakage."
                    emit_security_event(
                        event_type="output_secret_leak_blocked",
                        severity="CRITICAL",
                        action="BLOCKED",
                        risk_score=1.0,
                        raw_payload_for_fingerprint=content,
                        details={
                            "types": [s.secret_type for s in secrets],
                            "count": len(secrets),
                            "masked_previews": [s.masked_preview for s in secrets],
                        },
                    )
                    return OutputSecurityAssessment(
                        is_blocked=True,
                        is_redacted=False,
                        sanitized_text="[BLOCKED BY SENTINELAI: Generated response contained sensitive credential or key leakage]",
                        leaks_detected=leaks,
                        action="BLOCKED",
                        reason=reason,
                    )
                else:
                    # Redact secrets in text
                    current_text, _ = self.secret_scanner.redact(current_text)
                    is_redacted = True

        # 4. Check for PII Leakage
        if self.settings.output_redact_pii:
            pii_entities = self.pii_scanner.detect(current_text)
            if pii_entities:
                for p in pii_entities:
                    leaks.append(f"PII_{p.entity_type}")
                current_text, _ = self.pii_scanner.redact(current_text)
                is_redacted = True

        if is_redacted:
            emit_security_event(
                event_type="output_sanitized",
                severity="MEDIUM",
                action="REDACTED",
                risk_score=0.60,
                raw_payload_for_fingerprint=content,
                details={"leaks_count": len(leaks), "leaks": leaks},
            )
            reason = f"Sanitized {len(leaks)} sensitive entity(ies) in output."

        return OutputSecurityAssessment(
            is_blocked=is_blocked,
            is_redacted=is_redacted,
            sanitized_text=current_text,
            leaks_detected=leaks,
            action="REDACTED" if is_redacted else "ALLOWED",
            reason=reason,
        )


class StreamingOutputSanitizer:
    """Stateful sanitizer for streaming SSE response chunks."""

    def __init__(self, output_guard: OutputGuard, health_safety_engine: Any = None):
        self.output_guard = output_guard
        self.health_safety_engine = health_safety_engine
        self.accumulated = ""
        self.blocked = False

    def process_chunk(self, delta_text: str | None, is_last: bool = False) -> str | None:
        """Process incoming chunk delta, detecting and redacting sensitive outputs."""
        if delta_text:
            self.accumulated += delta_text

        if self.blocked or not delta_text:
            return None

        # 1. Check accumulated stream for critical leaks (e.g. private keys, critical secrets)
        assessment = self.output_guard.inspect_and_sanitize(self.accumulated)
        if assessment.is_blocked:
            self.blocked = True
            return "\n[BLOCKED BY SENTINELAI: CRITICAL LEAK DETECTED]"

        # 2. Check accumulated stream for unsafe medical treatment
        if self.health_safety_engine:
            _, h_assessment = self.health_safety_engine.evaluate_output(self.accumulated)
            if h_assessment.is_blocked:
                self.blocked = True
                return "\n[BLOCKED BY SENTINELAI: Unsafe medical treatment instruction blocked]"

        # 3. Sanitize current delta for PII and secrets
        delta_assessment = self.output_guard.inspect_and_sanitize(delta_text)
        if delta_assessment.is_blocked:
            self.blocked = True
            return "\n[BLOCKED BY SENTINELAI: CRITICAL LEAK DETECTED]"

        result = delta_assessment.sanitized_text
        if is_last and self.health_safety_engine:
            clean_res, _ = self.health_safety_engine.evaluate_output(self.accumulated)
            if clean_res != self.accumulated and clean_res.endswith("\n\n---\n*MEDICAL DISCLAIMER: SentinelAI provides general informational content only, not personal medical advice, clinical diagnosis, or treatment. Always consult a qualified healthcare provider with any health questions.*"):
                from sentinelai.security.health_safety import STANDARD_MEDICAL_DISCLAIMER
                if STANDARD_MEDICAL_DISCLAIMER not in self.accumulated:
                    result += STANDARD_MEDICAL_DISCLAIMER

        return result


_output_guard_instance: OutputGuard | None = None


def get_output_guard() -> OutputGuard:
    """Dependency provider for OutputGuard singleton."""
    global _output_guard_instance
    if _output_guard_instance is None:
        _output_guard_instance = OutputGuard()
    return _output_guard_instance
