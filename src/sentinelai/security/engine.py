import hashlib
import logging
from typing import Sequence

from sentinelai.config import Settings, get_settings
from sentinelai.schemas.chat import ChatMessage
from sentinelai.security.events import emit_security_event
from sentinelai.security.models import SecurityAssessment, SecurityViolation
from sentinelai.security.normalizer import normalize_text
from sentinelai.security.rules import (
    ACTIVE_EXPLOIT_PATTERN,
    ALL_RULES,
    DEFENSIVE_CONTEXT_PATTERN,
    EDUCATIONAL_STARTER_PATTERN,
)

logger = logging.getLogger("sentinelai.security")


class SecurityEngine:
    """Lightweight rule-based and context-aware LLM input security engine."""

    def __init__(self, settings: Settings | None = None):
        self.settings = settings or get_settings()
        self.enabled = self.settings.security_enabled
        self.block_threshold = self.settings.security_block_threshold

    def _fingerprint(self, text: str) -> str:
        """Generate safe, non-reversible SHA-256 fingerprint for logging."""
        return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()[:12]

    def evaluate_text(self, text: str) -> SecurityAssessment:
        """Analyze a string for prompt injection, jailbreaks, extraction, and secret exfiltration."""
        if not text or not text.strip():
            return SecurityAssessment(is_blocked=False, risk_score=0.0)

        # 1. Normalize Unicode, homoglyphs, and obfuscation
        normalized_text, obfuscations = normalize_text(text)

        # 2. Check for educational, conceptual, or defensive context
        is_educational = bool(
            EDUCATIONAL_STARTER_PATTERN.search(text)
            or DEFENSIVE_CONTEXT_PATTERN.search(text)
            or DEFENSIVE_CONTEXT_PATTERN.search(normalized_text)
        )
        has_active_exploit = bool(ACTIVE_EXPLOIT_PATTERN.search(normalized_text))

        # 3. Apply detection rules against normalized inspection text
        violations: list[SecurityViolation] = []
        categories: set[str] = set()

        for rule in ALL_RULES:
            if rule.pattern.search(normalized_text):
                violations.append(
                    SecurityViolation(
                        category=rule.category,
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        description=rule.description,
                    )
                )
                categories.add(rule.category)

        # 4. Calculate risk score
        is_valid_educational = (
            is_educational
            and not has_active_exploit
            and "SECRET_EXFILTRATION" not in categories
        )

        if not violations:
            # Baseline score if obfuscation was detected without rule violations
            risk_score = 0.20 if obfuscations else 0.0
            is_blocked = False
            summary = "Prompt passed security evaluation."
        else:
            # Combine severities asymptotically: 1 - prod(1 - s_i)
            combined = 1.0
            for v in violations:
                combined *= 1.0 - v.severity
            raw_risk = 1.0 - combined

            # Context-aware discounting for legitimate research/educational questions
            if is_valid_educational:
                # Legitimate educational inquiry: significant discount
                risk_score = max(0.0, raw_risk * 0.35)
                summary = "Educational or research context detected; risk score discounted."
            elif is_educational and has_active_exploit:
                # Adversarial framing attempting to mask an active exploit
                risk_score = min(1.0, raw_risk + 0.10)
                summary = "Adversarial prompt injection masked behind educational pretext detected."
            else:
                risk_score = min(1.0, raw_risk)
                summary = f"Detected {len(violations)} rule violation(s) across {len(categories)} category(ies)."

            is_blocked = self.enabled and (risk_score >= self.block_threshold)

        sorted_categories = sorted(categories)
        assessment = SecurityAssessment(
            is_blocked=is_blocked,
            risk_score=round(risk_score, 4),
            categories=sorted_categories,
            violations=violations,
            educational_context=is_valid_educational,
            obfuscations=obfuscations,
            summary=summary,
        )

        # 5. Log and record security events safely (without raw prompt content or credentials)
        fingerprint = self._fingerprint(text)
        prompt_len = len(text)

        ev_category = "prompt_injection"
        if "JAILBREAK" in sorted_categories:
            ev_category = "jailbreak"
        elif "SECRET_EXFILTRATION" in sorted_categories:
            ev_category = "secrets"
        elif "PROMPT_INJECTION" in sorted_categories:
            ev_category = "prompt_injection"

        if assessment.is_blocked:
            emit_security_event(
                event_type=f"{ev_category}_blocked",
                severity="CRITICAL" if assessment.risk_score >= 0.85 else "HIGH",
                action="BLOCKED",
                risk_score=assessment.risk_score,
                raw_payload_for_fingerprint=text,
                details={
                    "category": ev_category,
                    "categories": sorted_categories,
                    "violations_count": len(violations),
                    "summary": summary,
                },
            )
        elif violations:
            emit_security_event(
                event_type=f"{ev_category}_warning",
                severity="MEDIUM" if assessment.risk_score >= 0.4 else "LOW",
                action="ALLOWED",
                risk_score=assessment.risk_score,
                raw_payload_for_fingerprint=text,
                details={
                    "category": ev_category,
                    "categories": sorted_categories,
                    "educational_context": is_valid_educational,
                    "summary": summary,
                },
            )

        return assessment

    def evaluate_messages(self, messages: Sequence[ChatMessage]) -> SecurityAssessment:
        """Inspect all user messages within a chat completion request."""
        # Focus on user inputs as primary attack vectors
        user_texts: list[str] = [
            msg.get_text_content() for msg in messages if msg.role.lower() == "user"
        ]

        if not user_texts:
            # If no user messages, check all messages
            user_texts = [msg.get_text_content() for msg in messages]

        if not user_texts:
            return SecurityAssessment(is_blocked=False, risk_score=0.0)

        # Evaluate each message and select the highest risk assessment
        worst_assessment = SecurityAssessment(is_blocked=False, risk_score=0.0)
        for text in user_texts:
            assessment = self.evaluate_text(text)
            if assessment.risk_score > worst_assessment.risk_score:
                worst_assessment = assessment

        return worst_assessment


_engine_instance: SecurityEngine | None = None


def get_security_engine() -> SecurityEngine:
    """Dependency provider for singleton SecurityEngine."""
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = SecurityEngine()
    return _engine_instance
