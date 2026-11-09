from typing import Any
from fastapi import APIRouter, Depends, status
from pydantic import BaseModel, Field

from sentinelai.security.context_scanner import (
    ContextScanResult,
    ContextSecurityScanner,
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
