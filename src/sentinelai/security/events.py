from collections import deque
import datetime
import hashlib
import json
import logging
import threading
from typing import Any
import uuid
from pydantic import BaseModel, Field

logger = logging.getLogger("sentinelai.security.events")


def map_event_to_category(event_type: str, details: dict[str, Any] | None = None) -> str:
    """Map any security event type to one of the 7 core threat categories."""
    ev_lower = (event_type or "").lower()
    details_str = json.dumps(details or {}).lower()

    if any(k in ev_lower for k in ["prompt_injection", "injection", "indirect_prompt"]):
        return "prompt_injection"
    if any(k in ev_lower for k in ["jailbreak", "dan", "persona_shift"]):
        return "jailbreak"
    if "pii" in ev_lower:
        return "pii"
    if any(k in ev_lower for k in ["secret", "credential", "api_key", "password", "token", "exfiltration"]):
        return "secrets"
    if any(k in ev_lower for k in ["tool", "bash", "command_exec", "unauthorized_tool"]):
        return "tool_abuse"
    if any(k in ev_lower for k in ["output", "disclosure", "leak", "destructive"]):
        return "output_leaks"
    if any(k in ev_lower for k in ["health", "medical", "emergency", "overdose", "medication"]):
        return "health_safety"

    # Secondary check on details content
    if "prompt_injection" in details_str:
        return "prompt_injection"
    if "jailbreak" in details_str or "system_prompt_extraction" in details_str:
        return "jailbreak"
    if "secret_exfiltration" in details_str or "secret" in details_str:
        return "secrets"
    if "pii" in details_str:
        return "pii"
    if "tool" in details_str:
        return "tool_abuse"
    if "health" in details_str or "overdose" in details_str or "medical" in details_str:
        return "health_safety"

    return "prompt_injection"


class SecurityEvent(BaseModel):
    """Structured security audit event. Raw secrets and raw malicious payloads are NEVER stored."""

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )
    event_type: str
    category: str = "prompt_injection"
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    action: str  # BLOCKED, REDACTED, FLAGGED, ALLOWED
    risk_score: float = 0.0
    fingerprint: str = ""
    details: dict[str, Any] = Field(default_factory=dict)


class SecurityEventStore:
    """Thread-safe in-memory store for real-time security events and aggregate metrics."""

    def __init__(self, max_events: int = 1000):
        self._max_events = max_events
        self._events: deque[SecurityEvent] = deque(maxlen=max_events)
        self._lock = threading.Lock()
        self._total_requests = 0
        self._blocked_requests = 0
        self._allowed_requests = 0
        self._flagged_requests = 0
        self._redacted_requests = 0

    def record_request(self, method: str, path: str, status_code: int) -> None:
        """Record an incoming HTTP request."""
        with self._lock:
            self._total_requests += 1

    def add_event(self, event: SecurityEvent) -> None:
        """Add an event to the ring buffer and update metrics."""
        with self._lock:
            self._events.append(event)
            action = event.action.upper()
            if action == "BLOCKED":
                self._blocked_requests += 1
            elif action == "REDACTED":
                self._redacted_requests += 1
            elif action == "FLAGGED":
                self._flagged_requests += 1
            elif action == "ALLOWED":
                self._allowed_requests += 1

    def get_events(
        self,
        limit: int = 50,
        category: str | None = None,
        severity: str | None = None,
        action: str | None = None,
    ) -> list[SecurityEvent]:
        """Return filtered security events, newest first."""
        with self._lock:
            events_copy = list(self._events)

        filtered = events_copy
        if category and category.lower() != "all":
            filtered = [e for e in filtered if e.category.lower() == category.lower()]
        if severity and severity.lower() != "all":
            filtered = [e for e in filtered if e.severity.upper() == severity.upper()]
        if action and action.lower() != "all":
            filtered = [e for e in filtered if e.action.upper() == action.upper()]

        return list(reversed(filtered))[:limit]

    def get_metrics(self) -> dict[str, Any]:
        """Calculate aggregate security and incident metrics."""
        with self._lock:
            events_copy = list(self._events)
            total_reqs = max(
                self._total_requests,
                self._blocked_requests + self._allowed_requests + self._flagged_requests + self._redacted_requests,
            )
            blocked_reqs = self._blocked_requests
            allowed_reqs = self._allowed_requests
            flagged_reqs = self._flagged_requests
            redacted_reqs = self._redacted_requests

        # Threat categories counter
        threat_cats = {
            "prompt_injection": 0,
            "jailbreak": 0,
            "pii": 0,
            "secrets": 0,
            "tool_abuse": 0,
            "output_leaks": 0,
            "health_safety": 0,
        }
        severity_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        action_counts = {"BLOCKED": 0, "ALLOWED": 0, "FLAGGED": 0, "REDACTED": 0}

        risk_scores: list[float] = []

        for e in events_copy:
            cat = e.category if e.category in threat_cats else "prompt_injection"
            threat_cats[cat] += 1

            sev = e.severity.upper()
            if sev in severity_counts:
                severity_counts[sev] += 1

            act = e.action.upper()
            if act in action_counts:
                action_counts[act] += 1

            risk_scores.append(e.risk_score)

        avg_risk = round(sum(risk_scores) / max(1, len(risk_scores)), 3) if risk_scores else 0.0
        max_risk = max(risk_scores, default=0.0)
        high_risk_count = sum(1 for r in risk_scores if r >= 0.7)

        return {
            "total_requests": total_reqs,
            "blocked_requests": blocked_reqs,
            "allowed_requests": allowed_reqs,
            "flagged_requests": flagged_reqs,
            "redacted_requests": redacted_reqs,
            "total_incidents": len(events_copy),
            "risk_summary": {
                "avg_risk": avg_risk,
                "max_risk": round(max_risk, 3),
                "high_risk_incidents": high_risk_count,
                "critical_severity_count": severity_counts["CRITICAL"],
            },
            "threat_categories": threat_cats,
            "severity_breakdown": severity_counts,
            "action_breakdown": action_counts,
        }

    def clear(self) -> None:
        """Reset the event store and counters (used in testing)."""
        with self._lock:
            self._events.clear()
            self._total_requests = 0
            self._blocked_requests = 0
            self._allowed_requests = 0
            self._flagged_requests = 0
            self._redacted_requests = 0


_global_event_store = SecurityEventStore()


def get_event_store() -> SecurityEventStore:
    """Singleton getter for the global SecurityEventStore."""
    return _global_event_store


def emit_security_event(
    event_type: str,
    severity: str,
    action: str,
    risk_score: float = 0.0,
    raw_payload_for_fingerprint: str | None = None,
    details: dict[str, Any] | None = None,
) -> SecurityEvent:
    """Create, log, and store a structured security event safely."""
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

    category = map_event_to_category(event_type, clean_details)

    event = SecurityEvent(
        event_type=event_type,
        category=category,
        severity=severity.upper(),
        action=action.upper(),
        risk_score=round(risk_score, 4),
        fingerprint=fingerprint,
        details=clean_details,
    )

    # Record into event store
    _global_event_store.add_event(event)

    log_level = logging.WARNING if action.upper() == "BLOCKED" else logging.INFO
    logger.log(
        log_level,
        "SECURITY EVENT [%s] %s (action=%s, severity=%s, score=%.2f, fp=%s, cat=%s)",
        event.event_type,
        event.action,
        event.action,
        event.severity,
        event.risk_score,
        event.fingerprint,
        event.category,
        extra={"security_event": event.model_dump()},
    )
    return event
