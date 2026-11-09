from typing import Any
from pydantic import BaseModel, Field


class SecurityViolation(BaseModel):
    """Specific rule violation detected in prompt."""

    category: str
    rule_id: str
    severity: float = Field(ge=0.0, le=1.0)
    description: str


class SecurityAssessment(BaseModel):
    """Complete evaluation report for a prompt or message set."""

    is_blocked: bool = False
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    categories: list[str] = Field(default_factory=list)
    violations: list[SecurityViolation] = Field(default_factory=list)
    educational_context: bool = False
    obfuscations: list[str] = Field(default_factory=list)
    summary: str = "Prompt passed security evaluation."

    def to_error_details(self) -> dict[str, Any]:
        """Format safe structured details for client error response."""
        return {
            "risk_score": round(self.risk_score, 2),
            "categories": self.categories,
            "explanations": [v.description for v in self.violations],
            "educational_context_detected": self.educational_context,
        }
