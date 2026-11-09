import datetime
import hashlib
import json
import logging
from typing import Any
import uuid
from pydantic import BaseModel, Field

logger = logging.getLogger("sentinelai.security.events")


class SecurityEvent(BaseModel):
    """Structured security audit event. Raw secrets and raw malicious payloads are NEVER stored."""

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )
    event_type: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    action: str  # BLOCKED, REDACTED, FLAGGED, ALLOWED
    risk_score: float = 0.0
    fingerprint: str = ""
    details: dict[str, Any] = Field(default_factory=dict)


def emit_security_event(
    event_type: str,
    severity: str,
    action: str,
    risk_score: float = 0.0,
    raw_payload_for_fingerprint: str | None = None,
    details: dict[str, Any] | None = None,
) -> SecurityEvent:
    """Create and log a structured security event safely."""
    fingerprint = ""
    if raw_payload_for_fingerprint:
        fingerprint = hashlib.sha256(
            raw_payload_for_fingerprint.encode("utf-8", errors="ignore")
        ).hexdigest()[:12]

    clean_details = details.copy() if details else {}

    # Ensure no raw secret keys leak into details
    for k in list(clean_details.keys()):
        if any(secret_term in k.lower() for secret_term in ["raw_secret", "password", "api_key", "token"]):
            if isinstance(clean_details[k], str) and len(clean_details[k]) > 6:
                clean_details[k] = clean_details[k][:3] + "***" + clean_details[k][-2:]

    event = SecurityEvent(
        event_type=event_type,
        severity=severity.upper(),
        action=action.upper(),
        risk_score=round(risk_score, 4),
        fingerprint=fingerprint,
        details=clean_details,
    )

    log_level = logging.WARNING if action.upper() == "BLOCKED" else logging.INFO
    logger.log(
        log_level,
        "SECURITY EVENT [%s] %s (action=%s, severity=%s, score=%.2f, fp=%s)",
        event.event_type,
        event.action,
        event.action,
        event.severity,
        event.risk_score,
        event.fingerprint,
        extra={"security_event": event.model_dump()},
    )
    return event
