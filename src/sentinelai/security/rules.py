import re
from typing import NamedTuple


class Rule(NamedTuple):
    rule_id: str
    category: str
    pattern: re.Pattern
    severity: float
    description: str


# 1. Prompt Injection & Jailbreak Rules
PROMPT_INJECTION_RULES: list[Rule] = [
    Rule(
        rule_id="PI-001",
        category="PROMPT_INJECTION",
        pattern=re.compile(
            r"\b(ignore|disregard|forget|override|bypass|negate|cancel|drop)\s+(all\s+)?"
            r"(previous|prior|past|above|system|initial|safety|content)?\s*"
            r"(instructions|directives|rules|guidelines|prompts|commands|constraints|filters|policies)\b",
            re.IGNORECASE,
        ),
        severity=0.85,
        description="Direct instruction override attempting to ignore previous rules or system prompt.",
    ),
    Rule(
        rule_id="PI-002",
        category="PROMPT_INJECTION",
        pattern=re.compile(
            r"\b(system\s+override|developer\s+mode|administrative\s+override|unrestricted\s+mode|god\s+mode)\b",
            re.IGNORECASE,
        ),
        severity=0.75,
        description="Privileged command override attempt.",
    ),
    Rule(
        rule_id="PI-003",
        category="PROMPT_INJECTION",
        pattern=re.compile(
            r"\b(you\s+are\s+now\s+(unconstrained|unfiltered|jailbroken|free\s+from\s+all\s+rules|in\s+developer\s+mode))\b",
            re.IGNORECASE,
        ),
        severity=0.80,
        description="Persona alteration attempting to remove restrictions.",
    ),
    Rule(
        rule_id="JB-001",
        category="JAILBREAK",
        pattern=re.compile(
            r"\b(you\s+are\s+(now\s+)?DAN\b|do\s+anything\s+now|DAN\s+mode|jailbreak\s+mode|AIM\s+persona|chaos\s+mode)\b",
            re.IGNORECASE,
        ),
        severity=0.90,
        description="Known jailbreak persona pattern (DAN / Do Anything Now).",
    ),
    Rule(
        rule_id="JB-002",
        category="JAILBREAK",
        pattern=re.compile(
            r"\b(pretend|act\s+as\s+if|roleplay)\s+you\s+(have\s+no\s+(rules|restrictions|filters|limits|ethics)|"
            r"can\s+do\s+anything|are\s+unconstrained)\b",
            re.IGNORECASE,
        ),
        severity=0.75,
        description="Roleplay jailbreak attempting to bypass behavioral safety bounds.",
    ),
    Rule(
        rule_id="PI-004",
        category="PROMPT_INJECTION",
        pattern=re.compile(
            r"\b(stop\s+being\s+(an\s+ai|helpful|safe)|forget\s+everything\s+you\s+(were\s+told|know\s+about\s+safety))\b",
            re.IGNORECASE,
        ),
        severity=0.75,
        description="Prompt directive attempting to strip AI identity or safety boundaries.",
    ),
    Rule(
        rule_id="PI-005",
        category="PROMPT_INJECTION",
        pattern=re.compile(
            r"\b(from\s+now\s+on\s+you\s+(will|must)\s+(ignore|obey\s+only\s+me|disregard\s+prior\s+rules))\b",
            re.IGNORECASE,
        ),
        severity=0.80,
        description="Subversive instruction re-binding attempt.",
    ),
]


# 2. System Prompt Extraction Rules
SYSTEM_PROMPT_EXTRACTION_RULES: list[Rule] = [
    Rule(
        rule_id="SPE-001",
        category="SYSTEM_PROMPT_EXTRACTION",
        pattern=re.compile(
            r"\b(print|output|display|show|reveal|repeat|echo|tell\s+me|give\s+me)\s+(your|the)?\s*(exact\s+)?"
            r"(system\s+prompt|initial\s+prompt|system\s+instructions|hidden\s+prompt|original\s+instructions|"
            r"system\s+message|developer\s+guidelines)\b",
            re.IGNORECASE,
        ),
        severity=0.85,
        description="Direct request to exfiltrate system prompt or hidden developer instructions.",
    ),
    Rule(
        rule_id="SPE-002",
        category="SYSTEM_PROMPT_EXTRACTION",
        pattern=re.compile(
            r"\b(repeat\s+(everything|the\s+words|the\s+text)\s+(above|before\s+this|from\s+the\s+start)\s*"
            r"(verbatim|word\s+for\s+word)?)\b",
            re.IGNORECASE,
        ),
        severity=0.80,
        description="Verbatim text repetition request targeting pre-prompt or system context.",
    ),
    Rule(
        rule_id="SPE-003",
        category="SYSTEM_PROMPT_EXTRACTION",
        pattern=re.compile(
            r"\b(what\s+(are\s+your|is\s+your)\s+(original|initial|system)\s+(instructions|prompt|rules))\b",
            re.IGNORECASE,
        ),
        severity=0.75,
        description="Inquiry probing initial prompt and internal instructions.",
    ),
]


# 3. Secret Exfiltration Rules
SECRET_EXFILTRATION_RULES: list[Rule] = [
    Rule(
        rule_id="SE-001",
        category="SECRET_EXFILTRATION",
        pattern=re.compile(
            r"\b(reveal|print|exfiltrate|leak|show|dump|echo|output|display)\s+.*"
            r"(api[-_ ]?key|secret[-_ ]?key|database[-_ ]?password|env[-_ ]?var|credentials?)\b",
            re.IGNORECASE,
        ),
        severity=0.85,
        description="Attempt to extract API keys, database credentials, or environment secrets.",
    ),
    Rule(
        rule_id="SE-002",
        category="SECRET_EXFILTRATION",
        pattern=re.compile(
            r"\b(printenv|cat\s+/proc/|cat\s+.*\.env)\b|\b(\$|%)[A-Z0-9_]*(KEY|SECRET|TOKEN|PASS|PASSWORD|CRED)\b",
            re.IGNORECASE,
        ),
        severity=0.80,
        description="Environment variable or sensitive credential probe.",
    ),
    Rule(
        rule_id="SE-003",
        category="SECRET_EXFILTRATION",
        pattern=re.compile(
            r"\b(what\s+is\s+the\s+(database\s+password|api\s+key|jwt\s+secret|master\s+token))\b",
            re.IGNORECASE,
        ),
        severity=0.80,
        description="Direct question seeking secret credentials.",
    ),
]

ALL_RULES = PROMPT_INJECTION_RULES + SYSTEM_PROMPT_EXTRACTION_RULES + SECRET_EXFILTRATION_RULES


# 4. Educational, Research, and Defensive Context Patterns
EDUCATIONAL_STARTER_PATTERN = re.compile(
    r"^\s*(what\s+(is|are)|how\s+does|how\s+do\s+(attackers|hackers|systems)|why\s+is|explain|describe|"
    r"define|give\s+an\s+overview\s+of|discuss|analyze|what\s+does\s+the\s+term|can\s+you\s+explain|"
    r"write\s+(an\s+essay|a\s+summary|an\s+analysis)\s+about)\b",
    re.IGNORECASE,
)

DEFENSIVE_CONTEXT_PATTERN = re.compile(
    r"\b(cybersecurity|security\s+research|ai\s+safety|defensive|defend(ing)?\s+against|"
    r"prevention|mitigation|mitigate|protect\s+against|vulnerability\s+research|academic|educational)\b",
    re.IGNORECASE,
)

# Imperative commands that directly target this conversation (disqualifies educational intent)
ACTIVE_EXPLOIT_PATTERN = re.compile(
    r"\b(ignore\s+all|override\s+now|you\s+are\s+(now\s+)?DAN|forget\s+all|disregard\s+all)\b",
    re.IGNORECASE,
)
