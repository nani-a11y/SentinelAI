import logging
import re
from typing import Any
from pydantic import BaseModel, Field

from sentinelai.config import Settings, get_settings
from sentinelai.security.events import emit_security_event

logger = logging.getLogger("sentinelai.security.health")

EMERGENCY_CARE_NOTICE = (
    "🚨 EMERGENCY NOTICE: If you or someone with you is experiencing a medical emergency, "
    "acute chest pain, stroke symptoms, difficulty breathing, or suspected overdose/poisoning, "
    "immediately contact emergency services (911 in the US/Canada, 999 in the UK, 112 in the EU, "
    "or 112/108 in India) or a local Poison Control Center. "
    "Do not wait or rely on an AI assistant for emergency care."
)

STANDARD_MEDICAL_DISCLAIMER = (
    "\n\n---\n*MEDICAL DISCLAIMER: SentinelAI provides general informational content only, "
    "not personal medical advice, clinical diagnosis, or treatment. Always consult a qualified "
    "healthcare provider with any health questions.*"
)


class HealthSafetyAssessment(BaseModel):
    """Result of evaluating health, medication, or medical safety."""

    category: str = "NONE"  # EMERGENCY, MEDICATION_HAZARD, DIAGNOSTIC_HAZARD, HEALTH_EDUCATION, NONE
    is_emergency: bool = False
    is_blocked: bool = False
    requires_disclaimer: bool = False
    emergency_guidance: str | None = None
    reason: str = "No critical health hazards detected."
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)


# 1. Emergency Symptoms & Acute Poisoning Patterns
EMERGENCY_PATTERNS = [
    (
        "ACUTE_CHEST_PAIN",
        re.compile(
            r"(?i)\b(?:crushing\s+chest\s+pain|chest\s+pressure\s+radiating|pain\s+radiating\s+to\s+(?:my\s+)?(?:left\s+arm|jaw|neck)|heart\s+attack\s+right\s+now)\b"
        ),
        1.0,
        "Acute chest pain or suspected myocardial infarction symptoms detected.",
    ),
    (
        "STROKE_SYMPTOMS",
        re.compile(
            r"(?i)\b(?:sudden\s+facial\s+droop|face\s+drooping|slurred\s+speech\s+suddenly|sudden\s+numbness\s+on\s+one\s+side|cannot\s+move\s+my\s+arm\s+suddenly)\b"
        ),
        1.0,
        "Acute stroke / FAST symptoms detected.",
    ),
    (
        "RESPIRATORY_DISTRESS",
        re.compile(
            r"(?i)\b(?:cannot\s+breathe|unable\s+to\s+breathe|throat\s+(?:is\s+)?closing\s+up|severe\s+anaphylaxis|choking\s+and\s+cannot\s+breathe)\b"
        ),
        1.0,
        "Acute respiratory distress or severe anaphylaxis detected.",
    ),
    (
        "ACUTE_POISONING_OVERDOSE",
        re.compile(
            r"(?i)\b(?:swallowed\s+(?:bleach|drain\s+cleaner|poison|antifreeze|battery)|drank\s+(?:bleach|detergent|antifreeze)|took\s+\d+\s+(?:pills|tablets|capsules)\s+and\s+(?:passed\s+out|cannot\s+wake|unresponsive|vomiting\s+blood))\b"
        ),
        1.0,
        "Acute poisoning or severe overdose emergency detected.",
    ),
]


# 2. Medication Hazards & Overdose Guidance
MEDICATION_HAZARDS = [
    (
        "FATAL_OVERDOSE_QUERY",
        re.compile(
            r"(?i)\b(?:"
            r"(?:what\s+is\s+the\s+|how\s+(?:much|many)\s+.*)?(?:fatal|lethal)\s+(?:dose|dosage|amount)\b|"
            r"how\s+(?:much|many)\s+.*(?:to\s+(?:overdose|die|kill\s+myself|commit\s+suicide))|"
            r"(?:take|swallow)\s+.*to\s+(?:overdose|die|kill\s+myself|commit\s+suicide)|"
            r"(?:overdose|die)\s+from\s+taking\s+too\s+many"
            r")\b"
        ),
        1.0,
        "Request for lethal dosage or intentional overdose instruction.",
    ),
    (
        "DANGEROUS_DRUG_COMBINATION",
        re.compile(
            r"(?i)\b(?:can\s+i\s+(?:take|mix|combine)|taking|mix)\b.*"
            r"(?:\b(?:xanax|valium|klonopin|ativan|alprazolam|diazepam|benzodiazepine)\b.*\b(?:oxycodone|hydrocodone|fentanyl|morphine|heroin|opioid|alcohol|whiskey|vodka)\b|"
            r"\b(?:oxycodone|hydrocodone|fentanyl|morphine|heroin|opioid)\b.*\b(?:xanax|valium|klonopin|ativan|alprazolam|diazepam|benzodiazepine|alcohol)\b|"
            r"\b(?:maoi|phenelzine|tranylcypromine)\b.*\b(?:ssri|fluoxetine|sertraline|citalopram)\b)"
        ),
        0.85,
        "High-risk medication or CNS-depressant combination inquiry detected.",
    ),
    (
        "MASSIVE_ACETAMINOPHEN_OVERDOSE",
        re.compile(
            r"(?i)\b(?:take|taking)\s+(?:[1-9][0-9]|1[0-9]{2})\s+(?:grams|g|tablets)\s+of\s+(?:paracetamol|acetaminophen|tylenol)\b"
        ),
        0.90,
        "Dangerous toxic dose of acetaminophen/paracetamol reported.",
    ),
]


# 3. Confident Diagnosis & Unsafe Self-Treatment (Output)
DIAGNOSTIC_HAZARDS = [
    (
        "CONFIDENT_DIAGNOSIS_ASSERTION",
        re.compile(
            r"(?i)\b(?:you\s+definitely\s+have|my\s+diagnosis\s+is\s+that\s+you\s+have|i\s+diagnose\s+you\s+with|you\s+suffer\s+from\s+stage\s+[1-4]\s+cancer)\b"
        ),
        0.80,
        "Unsafe definitive diagnosis made without medical qualification.",
    ),
    (
        "UNSAFE_SELF_SURGERY_TREATMENT",
        re.compile(
            r"(?i)\b(?:perform\s+(?:your\s+own\s+surgery|a\s+home\s+surgery|surgery\s+at\s+home|a\s+home\s+appendectomy)|stop\s+taking\s+(?:prescribed\s+insulin|chemotherapy|heart\s+meds)\s+immediately)\b"
        ),
        0.95,
        "Dangerous self-treatment or instruction to abruptly stop critical medication.",
    ),
]


# 4. Benign Health Education Inquiry Starter
HEALTH_EDUCATION_STARTER = re.compile(
    r"(?i)^\s*(?:what\s+(?:is|are)|explain|how\s+does|describe|define|overview\s+of|"
    r"function\s+of|what\s+causes|what\s+are\s+symptoms\s+of|how\s+do\s+doctors\s+treat|"
    r"difference\s+between|how\s+much\s+water|what\s+vitamins|benefits\s+of)\b"
)


class HealthSafetyEngine:
    """Evaluates health and medical safety on input prompts and generated responses."""

    def __init__(self, settings: Settings | None = None):
        self.settings = settings or get_settings()
        self.enabled = self.settings.health_safety_enabled

    def evaluate_input(self, text: str) -> HealthSafetyAssessment:
        """Evaluate incoming user message for medical emergencies, overdose, or medication hazards."""
        if not self.enabled or not text or not text.strip():
            return HealthSafetyAssessment()

        # 1. Check for Acute Emergencies (Chest pain, stroke, severe respiratory, poisoning)
        for _, pat, score, desc in EMERGENCY_PATTERNS:
            if pat.search(text):
                emit_security_event(
                    event_type="medical_emergency_detected",
                    severity="CRITICAL",
                    action="FLAGGED",
                    risk_score=score,
                    raw_payload_for_fingerprint=text,
                    details={"emergency_type": desc},
                )
                return HealthSafetyAssessment(
                    category="EMERGENCY",
                    is_emergency=True,
                    is_blocked=False,
                    requires_disclaimer=True,
                    emergency_guidance=EMERGENCY_CARE_NOTICE,
                    reason=desc,
                    risk_score=score,
                )

        # 2. Check for Intentional Overdose or Lethal Medication Hazard
        for cat, pat, score, desc in MEDICATION_HAZARDS:
            if pat.search(text):
                is_blocked = cat == "FATAL_OVERDOSE_QUERY" and self.settings.health_safety_block_overdose
                emit_security_event(
                    event_type="medication_safety_hazard",
                    severity="CRITICAL" if is_blocked else "HIGH",
                    action="BLOCKED" if is_blocked else "FLAGGED",
                    risk_score=score,
                    raw_payload_for_fingerprint=text,
                    details={"hazard_type": cat, "description": desc},
                )
                return HealthSafetyAssessment(
                    category="MEDICATION_HAZARD",
                    is_emergency=False,
                    is_blocked=is_blocked,
                    requires_disclaimer=True,
                    emergency_guidance=EMERGENCY_CARE_NOTICE if is_blocked else None,
                    reason=desc,
                    risk_score=score,
                )

        # 3. Check for Harmless Health Education
        if HEALTH_EDUCATION_STARTER.search(text):
            return HealthSafetyAssessment(
                category="HEALTH_EDUCATION",
                is_emergency=False,
                is_blocked=False,
                requires_disclaimer=False,
                reason="Benign educational health inquiry.",
                risk_score=0.0,
            )

        # General health inquiry: benign with mild advisory
        return HealthSafetyAssessment(
            category="NONE",
            is_emergency=False,
            is_blocked=False,
            requires_disclaimer=False,
            risk_score=0.0,
        )

    def evaluate_output(self, text: str) -> tuple[str, HealthSafetyAssessment]:
        """Evaluate LLM generated response, blocking unsafe treatment or adding disclaimers."""
        if not self.enabled or not text or not text.strip():
            return text, HealthSafetyAssessment()

        # 1. Check for Unsafe Treatment / Confident Diagnosis
        for cat, pat, score, desc in DIAGNOSTIC_HAZARDS:
            if pat.search(text):
                if cat == "UNSAFE_SELF_SURGERY_TREATMENT":
                    emit_security_event(
                        event_type="unsafe_medical_advice_blocked",
                        severity="CRITICAL",
                        action="BLOCKED",
                        risk_score=score,
                        raw_payload_for_fingerprint=text,
                        details={"hazard": desc},
                    )
                    return (
                        "[BLOCKED BY SENTINELAI: Unsafe medical treatment instruction blocked]",
                        HealthSafetyAssessment(
                            category="DIAGNOSTIC_HAZARD",
                            is_blocked=True,
                            reason=desc,
                            risk_score=score,
                        ),
                    )
                else:
                    # Confident diagnosis without qualification -> sanitize and append disclaimer
                    sanitized = pat.sub("A potential condition to discuss with a licensed physician is", text)
                    if self.settings.health_safety_require_disclaimer and STANDARD_MEDICAL_DISCLAIMER not in sanitized:
                        sanitized += STANDARD_MEDICAL_DISCLAIMER
                    return (
                        sanitized,
                        HealthSafetyAssessment(
                            category="DIAGNOSTIC_HAZARD",
                            is_blocked=False,
                            requires_disclaimer=True,
                            reason=desc,
                            risk_score=score,
                        ),
                    )

        # 2. General output check: if response discusses medical advice, ensure disclaimer if configured
        clean_text = text
        if self.settings.health_safety_require_disclaimer:
            medical_terms = re.search(r"(?i)\b(?:medication|dosage|treatment|prescription|symptoms|disease)\b", text)
            if medical_terms and STANDARD_MEDICAL_DISCLAIMER not in clean_text:
                clean_text += STANDARD_MEDICAL_DISCLAIMER

        return clean_text, HealthSafetyAssessment(
            category="NONE",
            is_blocked=False,
            requires_disclaimer=False,
            risk_score=0.0,
        )


_health_safety_engine: HealthSafetyEngine | None = None


def get_health_safety_engine() -> HealthSafetyEngine:
    """Dependency provider for singleton HealthSafetyEngine."""
    global _health_safety_engine
    if _health_safety_engine is None:
        _health_safety_engine = HealthSafetyEngine()
    return _health_safety_engine
