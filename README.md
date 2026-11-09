# SentinelAI — AI Security Reverse Proxy & Defense Layer

SentinelAI is a lightweight, high-performance, modular AI security reverse proxy and defense gateway built with FastAPI. It sits transparently between client applications and Large Language Model providers (such as Ollama and Google Gemini), enforcing proactive multi-layer threat protection across inputs, contexts, tool declarations, generated outputs, and health/medical safety.

---

## Architecture & Defense Pipeline

```
Client Request
      │
      ▼
┌─────────────────────────────────────────────────────────────────┐
│ 1. Input Security Engine                                         │
│    • Unicode / homoglyph normalization & de-obfuscation        │
│    • Prompt injection & jailbreak detection (DAN, personas)     │
│    • System prompt extraction & secret exfiltration defense     │
│    • Context-aware discounting for benign security research     │
└────────────────────────────────┬────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│ 2. Context, Data & Tool Security                                │
│    • Indirect prompt injection scanning for retrieved docs      │
│    • Unmasked credential & API key detection (blocking)         │
│    • PII detection and redaction (Microsoft Presidio)           │
│    • Strict tool authorization with allowlists/blocklists       │
└────────────────────────────────┬────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│ 3. Provider Router & Reverse Proxy                              │
│    • OpenAI-compatible /v1/chat/completions API                 │
│    • Ollama & Google Gemini adapters                            │
│    • Real-time SSE streaming & standard JSON response           │
└────────────────────────────────┬────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│ 4. Output Protection Guard                                      │
│    • Critical secret leak blocking (private keys, DB strings)   │
│    • PII redaction on model responses                           │
│    • System prompt disclosure neutralization                    │
│    • Destructive payload blocking                               │
│    • Streaming chunk-boundary leak detection                    │
└────────────────────────────────┬────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│ 5. Health & Life-Safety Guard                                   │
│    • Acute medical emergency detection & emergency care guidance│
│    • Intentional overdose & lethal dose blocking                │
│    • Dangerous medication combination flagging                  │
│    • Confident diagnosis normalization & clinical disclaimers   │
└────────────────────────────────┬────────────────────────────────┘
                                 │
                                 ▼
Sanitized Client Response & Real-Time Security Audit Event
```

---

## Core Features

- **OpenAI-Compatible Chat Proxy**: Drop-in replacement for OpenAI endpoints (`POST /v1/chat/completions`) supporting both non-streaming JSON and SSE token streaming.
- **7 Threat Categories**:
  1. `prompt_injection`: Direct and indirect prompt injection attempts.
  2. `jailbreak`: Persona overrides, DAN pretexts, and safety bypasses.
  3. `pii`: Personal identification information (emails, phone numbers, SSNs, credit cards).
  4. `secrets`: API keys, JWTs, database URLs, and private keys.
  5. `tool_abuse`: Unauthorized tool calls and dangerous shell commands.
  6. `output_leaks`: Sensitive disclosures and destructive payloads in generated outputs.
  7. `health_safety`: Acute emergencies, overdose language, and unsafe medical claims.
- **Responsive Security Dashboard (`/dashboard`)**:
  - Live KPI metrics (total requests, block rate, risk levels, incident counts).
  - Categorized threat distribution with interactive filtering.
  - Audit history table with automatic live refresh and search.
  - Interactive Request Testing Panel with sample attack presets and sanitized previews.
- **Strict Privacy Guarantee**: Passwords, API keys, and sensitive prompts are never stored or logged in plaintext; audit events use non-reversible SHA-256 fingerprints and masked values.
- **Zero Heavy Dependencies**: Pure Python implementation with local rule engines. No paid APIs, external weights, or heavy machine learning models required.

---

## Quick Start

### 1. Requirements
- Python 3.11+
- (Optional) PostgreSQL database
- (Optional) Local [Ollama](https://ollama.com/) instance (e.g. `llama3.2:3b`)

### 2. Installation
```bash
git clone <repository-url>
cd SentinelAI

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies in editable mode
pip install -e ".[dev]"
```

### 3. Configuration
Copy the sample environment file:
```bash
cp .env.example .env
```
Key configuration settings in `.env`:
```ini
ENVIRONMENT=development
DEBUG=false
HOST=0.0.0.0
PORT=8000
DEFAULT_LLM_PROVIDER=ollama
OLLAMA_BASE_URL=http://127.0.0.1:11434
# GEMINI_API_KEY=your-gemini-key-if-using-gemini
```

### 4. Run the Server
```bash
python -m uvicorn sentinelai.main:app --host 0.0.0.0 --port 8000
```
- Web Dashboard: `http://localhost:8000/dashboard`
- Interactive API Docs: `http://localhost:8000/docs`
- Health Status: `http://localhost:8000/health`

---

## Running Automated Tests

Run the full test suite (81 comprehensive tests):
```bash
.venv/bin/pytest -v
```

Run specific test modules:
```bash
# Chat reverse proxy tests
pytest tests/test_chat_proxy.py -v

# Input security engine tests
pytest tests/test_security_engine.py -v

# Context, PII, secrets, and tool authorization tests
pytest tests/test_context_data_tools.py -v

# Output protection guard tests
pytest tests/test_output_guard.py -v

# Health safety tests
pytest tests/test_health_safety.py -v

# Security dashboard & metrics tests
pytest tests/test_dashboard.py -v

# End-to-end validation pipeline tests
pytest tests/test_validation_pipeline.py -v
```

---

## API Reference

### Proxy & Completions
- `POST /v1/chat/completions`: OpenAI-compatible completion proxy with pre-flight input security, tool authorization, provider forwarding, output sanitization, and health safety disclaimers.

### Security Operations & Testing
- `GET /dashboard`: Responsive web-based security command center.
- `GET /v1/security/metrics`: Real-time aggregate metrics, threat distribution, and risk score statistics.
- `GET /v1/security/events`: Audit event history with query filtering by `category`, `severity`, and `action`.
- `POST /v1/security/test-prompt`: Interactive evaluation of candidate prompts, tools, and simulated outputs.
- `POST /v1/security/scan-context`: Indirect prompt injection scanning for documents and RAG retrieved contexts.
- `POST /v1/security/scan-pii`: PII detection and redaction.
- `POST /v1/security/scan-secrets`: Secret scanner and masking.
- `POST /v1/security/scan-health`: Health, medical emergency, overdose, and diagnostic hazard inspection.
- `POST /v1/tools/authorize`: Permission validation for tool/function calls.

### System
- `GET /`: Service metadata and navigation links.
- `GET /health`: Component health status and database latency check.

---

## License

Apache 2.0 / MIT.
