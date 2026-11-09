# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1.0 | :x:                |

---

## Reporting a Vulnerability

The SentinelAI maintainers take security issues seriously. If you discover a security vulnerability or exploit in SentinelAI, please report it responsibly.

**Please do NOT file a public issue on GitHub.**

Instead, please send an encrypted or direct email to the security team at **security@sentinelai.local** (or submit a confidential report through GitHub Private Vulnerability Reporting if available on the repository).

### Please include:
1. A clear description of the vulnerability and attack vector.
2. Steps to reproduce or a minimal proof-of-concept (PoC).
3. The potential impact on LLM reverse proxy consumers or internal data.
4. Any proposed remediations or patches.

---

## Response Timeline

- **Initial Acknowledgement**: Within 48 hours.
- **Triage & Assessment**: Within 5 business days.
- **Fix & Public Advisory**: Coordinated disclosure within 30 days after verification.

---

## Security Philosophy & Limitations

SentinelAI provides a defense-in-depth security layer for Generative AI applications aligned with the OWASP Top 10 for LLM Applications. 

However, no automated scanner or rule engine can guarantee 100% prevention against sophisticated adversarial attacks, zero-day jailbreaks, or novel prompt injection vectors. SentinelAI should be operated as part of a comprehensive security architecture alongside authentication, rate limiting, human-in-the-loop validation, and least-privilege tool execution.
