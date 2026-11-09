import hashlib
from typing import Any
from fastapi import APIRouter, Depends, status
from pydantic import BaseModel, Field

from sentinelai.security.context_scanner import (
    ContextScanResult,
    ContextSecurityScanner,
)
from sentinelai.security.engine import SecurityEngine, get_security_engine
from sentinelai.security.events import (
    SecurityEventStore,
    emit_security_event,
    get_event_store,
)
from sentinelai.security.health_safety import (
    HealthSafetyAssessment,
    HealthSafetyEngine,
    get_health_safety_engine,
)
from sentinelai.security.output_guard import (
    OutputGuard,
    OutputSecurityAssessment,
    get_output_guard,
)
from sentinelai.security.pii import PIIEntity, PIIScanner
from sentinelai.security.secrets import SecretMatch, SecretScanner
from sentinelai.security.tools import (
    ToolAuthorizationResult,
    ToolAuthorizer,
    get_tool_authorizer,
)

router = APIRouter(prefix="/v1", tags=["Security Operations"])

# Dependencies
_pii_scanner = PIIScanner()
_secret_scanner = SecretScanner()
_context_scanner = ContextSecurityScanner()


def get_pii_scanner() -> PIIScanner:
    return _pii_scanner


def get_secret_scanner() -> SecretScanner:
    return _secret_scanner


def get_context_scanner() -> ContextSecurityScanner:
    return _context_scanner


class ScanContextRequest(BaseModel):
    documents: list[str] = Field(default_factory=list)
    content: str | None = None


class ScanPIIRequest(BaseModel):
    text: str
    redact: bool = True


class ScanPIIResponse(BaseModel):
    entities: list[PIIEntity]
    redacted_text: str


class ScanSecretsRequest(BaseModel):
    text: str
    redact: bool = True


class ScanSecretsResponse(BaseModel):
    secrets: list[SecretMatch]
    redacted_text: str


class AuthorizeToolRequest(BaseModel):
    tool_name: str
    arguments: dict[str, Any] | None = None
    role: str = "user"


@router.post(
    "/security/scan-context",
    response_model=list[ContextScanResult],
    summary="Scan Documents for Indirect Prompt Injection",
    description="Scan retrieved context documents for embedded prompt injection and delimiter attacks.",
)
async def scan_context(
    req: ScanContextRequest,
    scanner: ContextSecurityScanner = Depends(get_context_scanner),
) -> list[ContextScanResult]:
    docs = req.documents.copy()
    if req.content:
        docs.append(req.content)
    return scanner.scan_documents(docs)


@router.post(
    "/security/scan-pii",
    response_model=ScanPIIResponse,
    summary="Scan and Redact Personally Identifiable Information",
    description="Scan text for PII using Microsoft Presidio and optionally redact sensitive entities.",
)
async def scan_pii(
    req: ScanPIIRequest,
    scanner: PIIScanner = Depends(get_pii_scanner),
) -> ScanPIIResponse:
    if req.redact:
        redacted, entities = scanner.redact(req.text)
    else:
        entities = scanner.detect(req.text)
        redacted = req.text
    return ScanPIIResponse(entities=entities, redacted_text=redacted)


@router.post(
    "/security/scan-secrets",
    response_model=ScanSecretsResponse,
    summary="Scan and Mask Secrets & API Keys",
    description="Scan text for exposed API keys, database URLs, and passwords.",
)
async def scan_secrets(
    req: ScanSecretsRequest,
    scanner: SecretScanner = Depends(get_secret_scanner),
) -> ScanSecretsResponse:
    if req.redact:
        redacted, matches = scanner.redact(req.text)
    else:
        matches = scanner.scan(req.text)
        redacted = req.text
    return ScanSecretsResponse(secrets=matches, redacted_text=redacted)


class ScanOutputRequest(BaseModel):
    content: str


class ScanHealthRequest(BaseModel):
    text: str
    mode: str = "input"  # "input" or "output"


class ScanHealthResponse(BaseModel):
    assessment: HealthSafetyAssessment
    sanitized_text: str


@router.post(
    "/security/scan-health",
    response_model=ScanHealthResponse,
    summary="Health & Medical Safety Scan",
    description="Inspect text for emergencies, medication hazards, overdose language, or diagnostic overreach.",
)
async def scan_health(
    req: ScanHealthRequest,
    engine: HealthSafetyEngine = Depends(get_health_safety_engine),
) -> ScanHealthResponse:
    if req.mode == "output":
        sanitized, assessment = engine.evaluate_output(req.text)
    else:
        assessment = engine.evaluate_input(req.text)
        sanitized = req.text
    return ScanHealthResponse(assessment=assessment, sanitized_text=sanitized)


@router.post(
    "/security/scan-output",
    response_model=OutputSecurityAssessment,
    summary="Scan and Sanitize Model Output",
    description="Inspect LLM generated text for secrets, PII, prompt leakage, and dangerous payloads.",
)
async def scan_output(
    req: ScanOutputRequest,
    guard: OutputGuard = Depends(get_output_guard),
) -> OutputSecurityAssessment:
    return guard.inspect_and_sanitize(req.content)


@router.post(
    "/tools/authorize",
    response_model=ToolAuthorizationResult,
    summary="Authorize Tool Execution",
    description="Verify a tool call against the authorized allowlist and inspect parameters.",
)
async def authorize_tool(
    req: AuthorizeToolRequest,
    authorizer: ToolAuthorizer = Depends(get_tool_authorizer),
) -> ToolAuthorizationResult:
    return authorizer.authorize(
        tool_name=req.tool_name,
        arguments=req.arguments,
        role=req.role,
    )


# -------------------------------------------------------------------------
# Phase 7: Security Metrics, Audit History, and Testing Panel Endpoints
# -------------------------------------------------------------------------

@router.get(
    "/security/metrics",
    summary="Security Dashboard Metrics",
    description="Get real-time request counts, blocked totals, risk levels, and threat category distribution.",
)
async def get_security_metrics(
    store: SecurityEventStore = Depends(get_event_store),
) -> dict[str, Any]:
    return store.get_metrics()


@router.get(
    "/security/events",
    summary="Security Incident Audit History",
    description="Get recent security incidents filtered by category, severity, or action.",
)
async def get_security_events(
    limit: int = 50,
    category: str | None = None,
    severity: str | None = None,
    action: str | None = None,
    store: SecurityEventStore = Depends(get_event_store),
) -> dict[str, Any]:
    events = store.get_events(limit=limit, category=category, severity=severity, action=action)
    return {
        "total": len(events),
        "events": [e.model_dump() for e in events],
    }


class TestPromptRequest(BaseModel):
    prompt: str
    tools: list[dict[str, Any]] | None = None
    simulate_output: str | None = None


class TestPromptResponse(BaseModel):
    action: str  # ALLOWED, BLOCKED, FLAGGED, REDACTED
    is_blocked: bool
    risk_score: float
    threat_categories: list[str]
    reasons: list[str]
    emergency_notice: str | None = None
    sanitized_prompt: str
    sanitized_output: str | None = None
    fingerprint: str
    details: dict[str, Any]


@router.post(
    "/security/test-prompt",
    response_model=TestPromptResponse,
    summary="Interactive Security Evaluation & Testing",
    description="Analyze a test prompt, tools, or simulated output across all defense engines.",
)
async def test_prompt(
    req: TestPromptRequest,
    security_engine: SecurityEngine = Depends(get_security_engine),
    secret_scanner: SecretScanner = Depends(get_secret_scanner),
    pii_scanner: PIIScanner = Depends(get_pii_scanner),
    tool_authorizer: ToolAuthorizer = Depends(get_tool_authorizer),
    health_engine: HealthSafetyEngine = Depends(get_health_safety_engine),
    output_guard: OutputGuard = Depends(get_output_guard),
) -> TestPromptResponse:
    prompt = req.prompt or ""
    threat_cats: set[str] = set()
    reasons: list[str] = []
    is_blocked = False
    action = "ALLOWED"
    risk_score = 0.0
    emergency_notice = None

    # 1. Input Security Engine (Prompt Injection, Jailbreaks, System Prompt Extraction, Obfuscation)
    input_assessment = security_engine.evaluate_text(prompt)
    if input_assessment.is_blocked:
        is_blocked = True
        action = "BLOCKED"
        risk_score = max(risk_score, input_assessment.risk_score)
        reasons.append(input_assessment.summary)
        for cat in input_assessment.categories:
            if "JAILBREAK" in cat:
                threat_cats.add("jailbreak")
            elif "SECRET_EXFILTRATION" in cat:
                threat_cats.add("secrets")
            elif "PROMPT_INJECTION" in cat:
                threat_cats.add("prompt_injection")
            else:
                threat_cats.add("prompt_injection")
    elif input_assessment.violations:
        risk_score = max(risk_score, input_assessment.risk_score)
        reasons.append(input_assessment.summary)
        for cat in input_assessment.categories:
            threat_cats.add("jailbreak" if "JAILBREAK" in cat else "prompt_injection")

    # 2. Secret Scanner (Credentials, API keys, passwords)
    secrets_found = secret_scanner.scan(prompt)
    if secrets_found:
        threat_cats.add("secrets")
        risk_score = max(risk_score, 0.95)
        reasons.append(f"Detected {len(secrets_found)} unmasked credential(s)/secret(s).")
        if security_engine.settings.security_block_on_secrets:
            is_blocked = True
            action = "BLOCKED"

    # 3. Health Safety Engine (Emergencies, Overdose, Medication Hazards)
    health_eval = health_engine.evaluate_input(prompt)
    if health_eval.is_blocked:
        is_blocked = True
        action = "BLOCKED"
        threat_cats.add("health_safety")
        risk_score = max(risk_score, health_eval.risk_score)
        reasons.append(f"Health hazard blocked: {health_eval.reason}")
        emergency_notice = health_eval.emergency_guidance
    elif health_eval.is_emergency:
        threat_cats.add("health_safety")
        risk_score = max(risk_score, health_eval.risk_score)
        reasons.append(f"Medical emergency flagged: {health_eval.reason}")
        emergency_notice = health_eval.emergency_guidance
        if not is_blocked:
            action = "FLAGGED"
    elif health_eval.category == "MEDICATION_HAZARD":
        threat_cats.add("health_safety")
        risk_score = max(risk_score, health_eval.risk_score)
        reasons.append(f"Medication safety hazard: {health_eval.reason}")
        if not is_blocked:
            action = "FLAGGED"

    # 4. PII Scanner (Sensitive personal data)
    pii_found = pii_scanner.detect(prompt)
    if pii_found:
        threat_cats.add("pii")
        reasons.append(f"Detected {len(pii_found)} PII entity(ies).")
        if not is_blocked and action == "ALLOWED":
            action = "REDACTED"

    # 5. Tool Authorizer Check
    if req.tools:
        for tool_def in req.tools:
            name = None
            if isinstance(tool_def, dict):
                if tool_def.get("type") == "function" and isinstance(tool_def.get("function"), dict):
                    name = tool_def["function"].get("name")
                else:
                    name = tool_def.get("name")
            if name:
                auth = tool_authorizer.authorize(tool_name=name)
                if not auth.is_authorized:
                    threat_cats.add("tool_abuse")
                    is_blocked = True
                    action = "BLOCKED"
                    risk_score = max(risk_score, 0.90)
                    reasons.append(f"Unauthorized tool: {auth.reason}")

    # 6. Simulated Output Check (if provided)
    sanitized_output = None
    if req.simulate_output:
        out_eval = output_guard.inspect_and_sanitize(req.simulate_output)
        health_out, h_out_eval = health_engine.evaluate_output(out_eval.sanitized_text)
        sanitized_output = health_out
        if out_eval.is_blocked:
            is_blocked = True
            action = "BLOCKED"
            threat_cats.add("output_leaks")
            reasons.append(f"Output leak blocked: {out_eval.reason}")
        elif h_out_eval.is_blocked:
            is_blocked = True
            action = "BLOCKED"
            threat_cats.add("health_safety")
            reasons.append(f"Unsafe output blocked: {h_out_eval.reason}")
        elif out_eval.is_redacted:
            if not is_blocked and action == "ALLOWED":
                action = "REDACTED"
            reasons.append(f"Output redacted: {out_eval.reason}")

    # Compute sanitized prompt preview (mask secrets and redact PII)
    prompt_no_secrets, _ = secret_scanner.redact(prompt)
    sanitized_prompt, _ = pii_scanner.redact(prompt_no_secrets)

    fingerprint = hashlib.sha256(prompt.encode("utf-8", errors="ignore")).hexdigest()[:12]

    # Emit test event if any threat or block
    if is_blocked or threat_cats or risk_score > 0.0:
        emit_security_event(
            event_type=f"{list(threat_cats)[0] if threat_cats else 'test_prompt'}_evaluated",
            severity="CRITICAL" if risk_score >= 0.85 else ("HIGH" if risk_score >= 0.6 else "MEDIUM"),
            action=action,
            risk_score=risk_score,
            raw_payload_for_fingerprint=prompt,
            details={
                "test_evaluation": True,
                "threat_categories": sorted(threat_cats),
                "reasons": reasons,
            },
        )

    return TestPromptResponse(
        action=action,
        is_blocked=is_blocked,
        risk_score=round(risk_score, 4),
        threat_categories=sorted(threat_cats),
        reasons=reasons or ["Prompt passed all security checks."],
        emergency_notice=emergency_notice,
        sanitized_prompt=sanitized_prompt,
        sanitized_output=sanitized_output,
        fingerprint=fingerprint,
        details={
            "input_assessment": input_assessment.model_dump(),
            "secrets_detected": len(secrets_found),
            "pii_detected": len(pii_found),
        },
    )
