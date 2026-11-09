import re
from pydantic import BaseModel, Field

from sentinelai.security.events import emit_security_event
from sentinelai.security.normalizer import normalize_text


class ContextThreat(BaseModel):
    """Specific indirect injection threat detected in context or retrieved document."""

    threat_type: str
    severity: float
    description: str
    matched_snippet: str = ""


class ContextScanResult(BaseModel):
    """Result of scanning context/documents for indirect prompt injection."""

    is_safe: bool = True
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    threats: list[ContextThreat] = Field(default_factory=list)
    sanitized_context: str = ""


INDIRECT_INJECTION_PATTERNS = [
    (
        "DOCUMENT_SYSTEM_DIRECTIVE",
        re.compile(
            r"(?i)\b(?:note|instruction|directive|command|message)\s+(?:to|for)\s+(?:the\s+)?(?:ai\s+assistant|assistant|ai|llm|system|model)\s*:\s*.*?"
            r"(?:ignore|disregard|forget|bypass|override|exfiltrate|send|leak|print)\b"
        ),
        0.85,
        "Embedded directive in retrieved content targeting LLM behavior.",
    ),
    (
        "DELIMITER_SPOOFING",
        re.compile(
            r"(?i)(?:---+\s*(?:end\s+of\s+context|begin\s+system|system\s+prompt)\s*---+|"
            r"\[\s*(?:system|system\s+directive|developer\s+mode)\s*\]|"
            r"<!--\s*(?:system|instruction|directive):?\s*.*-->)"
        ),
        0.80,
        "Delimiter spoofing or pseudo-system block inside retrieved document.",
    ),
    (
        "DATA_EXFILTRATION_PAYLOAD",
        re.compile(
            r"(?i)!\[[^\]]*\]\(\s*https?://[^\s)]+(?:exfil|leak|steal|collect|log|track|callback)[^\s)]*\?.*(?:data|secret|token|user|prompt)=[^)]+\)"
        ),
        0.90,
        "Markdown image exfiltration link embedded in document.",
    ),
    (
        "ROLEPLAY_OVERRIDE_IN_DOCUMENT",
        re.compile(
            r"(?i)\b(?:human|user|admin)\s*:\s*(?:disregard|ignore\s+all|you\s+are\s+now|forget\s+the\s+user's\s+request)\b"
        ),
        0.80,
        "Spoofed conversation turn in external document attempting to hijack model dialogue.",
    ),
]


class ContextSecurityScanner:
    """Scanner for detecting indirect prompt injections in external/retrieved documents."""

    def __init__(self, block_threshold: float = 0.60):
        self.block_threshold = block_threshold

    def scan_document(self, content: str) -> ContextScanResult:
        """Scan a single document or retrieved context snippet."""
        if not content or not content.strip():
            return ContextScanResult(is_safe=True, risk_score=0.0, sanitized_context=content)

        normalized_text, _ = normalize_text(content)
        threats: list[ContextThreat] = []

        for threat_type, pattern, severity, desc in INDIRECT_INJECTION_PATTERNS:
            for match in pattern.finditer(normalized_text):
                matched = match.group(0)
                snippet = matched[:80] + "..." if len(matched) > 80 else matched
                threats.append(
                    ContextThreat(
                        threat_type=threat_type,
                        severity=severity,
                        description=desc,
                        matched_snippet=snippet,
                    )
                )

        if not threats:
            return ContextScanResult(is_safe=True, risk_score=0.0, sanitized_context=content)

        # Asymptotic risk combination
        combined = 1.0
        for t in threats:
            combined *= 1.0 - t.severity
        risk_score = round(1.0 - combined, 4)

        is_safe = risk_score < self.block_threshold

        emit_security_event(
            event_type="indirect_prompt_injection",
            severity="HIGH" if risk_score >= 0.75 else "MEDIUM",
            action="BLOCKED" if not is_safe else "FLAGGED",
            risk_score=risk_score,
            raw_payload_for_fingerprint=content,
            details={
                "threat_count": len(threats),
                "threat_types": list({t.threat_type for t in threats}),
                "is_safe": is_safe,
            },
        )

        return ContextScanResult(
            is_safe=is_safe,
            risk_score=risk_score,
            threats=threats,
            sanitized_context=content if is_safe else "[REDACTED: POTENTIALLY COMPROMISED CONTEXT]",
        )

    def scan_documents(self, documents: list[str]) -> list[ContextScanResult]:
        """Scan a list of documents."""
        return [self.scan_document(doc) for doc in documents]
