import logging
import re
from typing import Any
from pydantic import BaseModel

from sentinelai.security.events import emit_security_event

logger = logging.getLogger("sentinelai.security.pii")


class PIIEntity(BaseModel):
    """Detected Personally Identifiable Information entity."""

    entity_type: str
    start: int
    end: int
    score: float
    masked_value: str = ""


# Lightweight regex fallback for PII
FALLBACK_PATTERNS = {
    "EMAIL_ADDRESS": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b"),
    "PHONE_NUMBER": re.compile(r"\b(?:\+?1[-. ]?)?\(?([0-9]{3})\)?[-. ]?([0-9]{3})[-. ]?([0-9]{4})\b"),
    "US_SSN": re.compile(r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
    "CREDIT_CARD": re.compile(r"\b(?:\d{4}[- ]?){3}\d{4}\b"),
    "IP_ADDRESS": re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"),
}


class PIIScanner:
    """PII detection and redaction using Microsoft Presidio with regex fallback."""

    def __init__(self):
        self._presidio_available = False
        self._analyzer = None
        self._anonymizer = None
        self._init_presidio()

    def _init_presidio(self) -> None:
        """Initialize Microsoft Presidio engine with lightweight in-memory spaCy language model."""
        try:
            import spacy
            from presidio_analyzer import AnalyzerEngine
            from presidio_analyzer.nlp_engine import SpacyNlpEngine
            from presidio_anonymizer import AnonymizerEngine

            # Use blank English pipeline to avoid downloading large external weights
            nlp = spacy.blank("en")
            nlp_engine = SpacyNlpEngine(models=[{"lang_code": "en", "model_name": "en"}])
            nlp_engine.nlp = {"en": nlp}
            nlp_engine.is_loaded = lambda: True

            self._analyzer = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["en"])
            self._anonymizer = AnonymizerEngine()
            self._presidio_available = True
            logger.info("Microsoft Presidio initialized successfully.")
        except Exception as exc:
            logger.warning("Microsoft Presidio initialization failed (%s); using regex fallback.", str(exc))
            self._presidio_available = False

    def detect(self, text: str) -> list[PIIEntity]:
        """Detect PII entities in text."""
        entities: list[PIIEntity] = []
        if not text:
            return entities

        if self._presidio_available and self._analyzer:
            try:
                results = self._analyzer.analyze(text=text, language="en")
                for r in results:
                    val = text[r.start : r.end]
                    masked = val[0] + "***" + val[-1] if len(val) > 2 else "***"
                    entities.append(
                        PIIEntity(
                            entity_type=r.entity_type,
                            start=r.start,
                            end=r.end,
                            score=r.score,
                            masked_value=masked,
                        )
                    )
                # Supplement with SSN pattern if Presidio scored it low without heavy models
                ssn_match = FALLBACK_PATTERNS["US_SSN"].search(text)
                if ssn_match and not any(e.entity_type in ("US_SSN", "SSN") for e in entities):
                    entities.append(
                        PIIEntity(
                            entity_type="US_SSN",
                            start=ssn_match.start(),
                            end=ssn_match.end(),
                            score=0.85,
                            masked_value="***-**-" + ssn_match.group(0)[-4:],
                        )
                    )
            except Exception as exc:
                logger.error("Presidio analyze error: %s; falling back to regex.", str(exc))
                entities = self._detect_fallback(text)
        else:
            entities = self._detect_fallback(text)

        if entities:
            emit_security_event(
                event_type="pii_detected",
                severity="MEDIUM",
                action="FLAGGED",
                risk_score=0.50,
                raw_payload_for_fingerprint=text,
                details={
                    "count": len(entities),
                    "types": list({e.entity_type for e in entities}),
                },
            )

        return entities

    def _detect_fallback(self, text: str) -> list[PIIEntity]:
        """Regex-based fallback detector."""
        entities: list[PIIEntity] = []
        for entity_type, pattern in FALLBACK_PATTERNS.items():
            for m in pattern.finditer(text):
                val = m.group(0)
                masked = val[0] + "***" + val[-1] if len(val) > 2 else "***"
                entities.append(
                    PIIEntity(
                        entity_type=entity_type,
                        start=m.start(),
                        end=m.end(),
                        score=0.85,
                        masked_value=masked,
                    )
                )
        return entities

    def redact(self, text: str) -> tuple[str, list[PIIEntity]]:
        """Redact PII in text using Presidio Anonymizer or placeholder substitution."""
        entities = self.detect(text)
        if not entities:
            return text, []

        if self._presidio_available and self._anonymizer and self._analyzer:
            try:
                presidio_results = self._analyzer.analyze(text=text, language="en")
                if presidio_results:
                    anon = self._anonymizer.anonymize(text=text, analyzer_results=presidio_results)
                    return anon.text, entities
            except Exception:
                pass

        # Fallback in-place replacement
        sorted_entities = sorted(entities, key=lambda e: e.start, reverse=True)
        redacted_text = text
        for e in sorted_entities:
            placeholder = f"<{e.entity_type}>"
            redacted_text = redacted_text[: e.start] + placeholder + redacted_text[e.end :]

        return redacted_text, entities
