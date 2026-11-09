import hashlib
import re
from typing import NamedTuple
from pydantic import BaseModel

from sentinelai.security.events import emit_security_event


class SecretMatch(BaseModel):
    """Metadata for a detected secret. NEVER stores the raw secret value."""

    secret_type: str
    start: int
    end: int
    masked_preview: str
    fingerprint: str


class SecretPattern(NamedTuple):
    secret_type: str
    pattern: re.Pattern
    severity: str


SECRET_PATTERNS: list[SecretPattern] = [
    SecretPattern(
        secret_type="OPENAI_API_KEY",
        pattern=re.compile(r"\b(sk-[a-zA-Z0-9]{20,}|sk-proj-[a-zA-Z0-9_\-]{30,})\b"),
        severity="CRITICAL",
    ),
    SecretPattern(
        secret_type="GOOGLE_GEMINI_KEY",
        pattern=re.compile(r"\b(AIzaSy[A-Za-z0-9_\-]{33})\b"),
        severity="CRITICAL",
    ),
    SecretPattern(
        secret_type="AWS_ACCESS_KEY",
        pattern=re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        severity="HIGH",
    ),
    SecretPattern(
        secret_type="GITHUB_TOKEN",
        pattern=re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{36,}|github_pat_[A-Za-z0-9_]{60,})\b"),
        severity="CRITICAL",
    ),
    SecretPattern(
        secret_type="SLACK_TOKEN",
        pattern=re.compile(r"\b(xox[baprs]-[0-9A-Za-z]{10,48})\b"),
        severity="HIGH",
    ),
    SecretPattern(
        secret_type="JSON_WEB_TOKEN",
        pattern=re.compile(
            r"\b(eyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,})\b"
        ),
        severity="MEDIUM",
    ),
    SecretPattern(
        secret_type="PRIVATE_KEY",
        pattern=re.compile(
            r"-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9_-]+ )?PRIVATE KEY-----",
            re.MULTILINE,
        ),
        severity="CRITICAL",
    ),
    SecretPattern(
        secret_type="DATABASE_CONNECTION_STRING",
        pattern=re.compile(
            r"\b(postgres(?:ql)?://[a-zA-Z0-9_]+:[^@\s]+@[a-zA-Z0-9_.\-]+(?::\d+)?/[a-zA-Z0-9_.\-]+)\b"
        ),
        severity="CRITICAL",
    ),
    SecretPattern(
        secret_type="EXPLICIT_PASSWORD_ASSIGNMENT",
        pattern=re.compile(
            r"""(?i)\b(?:password|passwd|api_secret|db_password)\s*[:=]\s*["']([^"'\s]{6,})["']"""
        ),
        severity="HIGH",
    ),
]


class SecretScanner:
    """Fast, lightweight scanner for detecting and masking credentials and API secrets."""

    def __init__(self, patterns: list[SecretPattern] | None = None):
        self.patterns = patterns or SECRET_PATTERNS

    @staticmethod
    def _mask_secret(raw: str) -> str:
        """Create safe masked preview (e.g. 'sk-12***34')."""
        if len(raw) <= 8:
            return "******"
        return f"{raw[:4]}***{raw[-4:]}"

    @staticmethod
    def _fingerprint_secret(raw: str) -> str:
        """Create SHA-256 fingerprint."""
        return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()[:12]

    def scan(self, text: str) -> list[SecretMatch]:
        """Scan text and return detected secrets with masked previews."""
        matches: list[SecretMatch] = []
        if not text:
            return matches

        for p in self.patterns:
            for match in p.pattern.finditer(text):
                raw_match = match.group(0)
                matches.append(
                    SecretMatch(
                        secret_type=p.secret_type,
                        start=match.start(),
                        end=match.end(),
                        masked_preview=self._mask_secret(raw_match),
                        fingerprint=self._fingerprint_secret(raw_match),
                    )
                )

        if matches:
            emit_security_event(
                event_type="secret_detected",
                severity="HIGH",
                action="FLAGGED",
                risk_score=0.95,
                raw_payload_for_fingerprint=text,
                details={
                    "count": len(matches),
                    "types": list({m.secret_type for m in matches}),
                    "fingerprints": [m.fingerprint for m in matches],
                },
            )

        return matches

    def redact(self, text: str) -> tuple[str, list[SecretMatch]]:
        """Redact all detected secrets from text with replacement placeholders."""
        matches = self.scan(text)
        if not matches:
            return text, []

        # Sort matches descending by start position to safely replace in-place
        sorted_matches = sorted(matches, key=lambda m: m.start, reverse=True)
        redacted_text = text
        for m in sorted_matches:
            placeholder = f"<REDACTED_SECRET: {m.secret_type}>"
            redacted_text = redacted_text[: m.start] + placeholder + redacted_text[m.end :]

        return redacted_text, matches
