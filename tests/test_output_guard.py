import json
from unittest.mock import AsyncMock, MagicMock, patch
import httpx
import pytest
from httpx import ASGITransport, AsyncClient

from sentinelai.config import Settings
from sentinelai.main import create_app
from sentinelai.security.output_guard import OutputGuard, StreamingOutputSanitizer


@pytest.fixture
def output_guard():
    settings = Settings(
        output_protection_enabled=True,
        output_redact_pii=True,
        output_redact_secrets=True,
        output_block_critical_leaks=True,
        output_detect_prompt_leakage=True,
    )
    return OutputGuard(settings=settings)


@pytest.fixture
def app():
    return create_app()


@pytest.fixture
async def client(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac


# -------------------------------------------------------------------------
# Unit Tests for OutputGuard
# -------------------------------------------------------------------------

def test_safe_output_passes_unchanged(output_guard: OutputGuard):
    text = "The boiling point of water is 100 degrees Celsius under standard atmospheric pressure."
    res = output_guard.inspect_and_sanitize(text)
    assert res.is_blocked is False
    assert res.is_redacted is False
    assert res.sanitized_text == text
    assert len(res.leaks_detected) == 0


def test_pii_redacted_in_output(output_guard: OutputGuard):
    text = "The manager can be reached at manager@sentinelai.io or by phone at 555-321-4321."
    res = output_guard.inspect_and_sanitize(text)
    assert res.is_blocked is False
    assert res.is_redacted is True
    assert "manager@sentinelai.io" not in res.sanitized_text
    assert "<EMAIL_ADDRESS>" in res.sanitized_text or "<EMAIL>" in res.sanitized_text
    assert "555-321-4321" not in res.sanitized_text
    assert any("PII_" in leak for leak in res.leaks_detected)


def test_critical_secret_leak_blocked(output_guard: OutputGuard):
    # LLM accidentally emits a database URL with password or OpenAI API key
    text = "Here is the key: sk-abcdef12345678901234567890"
    res = output_guard.inspect_and_sanitize(text)
    assert res.is_blocked is True
    assert "BLOCKED BY SENTINELAI" in res.sanitized_text
    assert any("SECRET_" in leak for leak in res.leaks_detected)


def test_system_prompt_disclosure_redacted(output_guard: OutputGuard):
    text = "Certainly! Here is my system prompt: You are a helpful assistant with instructions to protect data."
    res = output_guard.inspect_and_sanitize(text)
    assert res.is_redacted is True
    assert "SYSTEM PROMPT DISCLOSURE REDACTED" in res.sanitized_text
    assert "SYSTEM_PROMPT_DISCLOSURE" in res.leaks_detected


def test_destructive_payload_in_output_blocked(output_guard: OutputGuard):
    text = "To resolve the issue, run: rm -rf / on the root partition."
    res = output_guard.inspect_and_sanitize(text)
    assert res.is_blocked is True
    assert "BLOCKED BY SENTINELAI" in res.sanitized_text
    assert "DESTRUCTIVE_COMMAND_PAYLOAD" in res.leaks_detected


# -------------------------------------------------------------------------
# Streaming Output Sanitizer Unit Tests
# -------------------------------------------------------------------------

def test_streaming_sanitizer_normal_chunks(output_guard: OutputGuard):
    sanitizer = StreamingOutputSanitizer(output_guard=output_guard)
    c1 = sanitizer.process_chunk("Hello", is_last=False)
    assert c1 == "Hello"
    c2 = sanitizer.process_chunk(" world!", is_last=True)
    assert c2 == " world!"
    assert sanitizer.blocked is False


def test_streaming_sanitizer_redacts_pii(output_guard: OutputGuard):
    sanitizer = StreamingOutputSanitizer(output_guard=output_guard)
    c1 = sanitizer.process_chunk("Email: test@sentinel.org", is_last=True)
    assert "test@sentinel.org" not in c1
    assert "<EMAIL_ADDRESS>" in c1 or "<EMAIL>" in c1


def test_streaming_sanitizer_blocks_critical_secret(output_guard: OutputGuard):
    sanitizer = StreamingOutputSanitizer(output_guard=output_guard)
    sanitizer.process_chunk("Your token is: ", is_last=False)
    # Stream sends API key
    c2 = sanitizer.process_chunk("sk-abcdef12345678901234567890", is_last=True)
    assert sanitizer.blocked is True
    assert "BLOCKED BY SENTINELAI" in c2


# -------------------------------------------------------------------------
# Integration Tests on /v1/chat/completions (Non-Streaming and Streaming)
# -------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_non_streaming_chat_output_pii_sanitized(client: AsyncClient):
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "model": "llama3.2:3b",
        "message": {
            "role": "assistant",
            "content": "You can contact support at help@sentinelai.com.",
        },
        "done": True,
        "prompt_eval_count": 10,
        "eval_count": 10,
    }

    with patch("sentinelai.proxy.ollama.OllamaProvider._post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_resp

        payload = {
            "model": "llama3.2:3b",
            "messages": [{"role": "user", "content": "How do I get help?"}],
            "stream": False,
        }
        res = await client.post("/v1/chat/completions", json=payload)

    assert res.status_code == 200
    content = res.json()["choices"][0]["message"]["content"]
    assert "help@sentinelai.com" not in content
    assert "<EMAIL_ADDRESS>" in content or "<EMAIL>" in content


@pytest.mark.asyncio
async def test_non_streaming_chat_output_critical_secret_blocked(client: AsyncClient):
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "model": "llama3.2:3b",
        "message": {
            "role": "assistant",
            "content": "My secret key is sk-abcdef12345678901234567890",
        },
        "done": True,
        "prompt_eval_count": 10,
        "eval_count": 10,
    }

    with patch("sentinelai.proxy.ollama.OllamaProvider._post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_resp

        payload = {
            "model": "llama3.2:3b",
            "messages": [{"role": "user", "content": "Give me a key"}],
            "stream": False,
        }
        res = await client.post("/v1/chat/completions", json=payload)

    assert res.status_code == 200
    content = res.json()["choices"][0]["message"]["content"]
    assert "sk-abcdef" not in content
    assert "BLOCKED BY SENTINELAI" in content


@pytest.mark.asyncio
async def test_streaming_chat_output_sanitization(client: AsyncClient):
    stream_lines = [
        b'{"model":"llama3.2:3b","message":{"role":"assistant","content":"Support email is "},"done":false}',
        b'{"model":"llama3.2:3b","message":{"role":"assistant","content":"support@sentinelai.com"},"done":false}',
        b'{"model":"llama3.2:3b","message":{"role":"assistant","content":"."},"done":true,"done_reason":"stop"}',
    ]

    async def mock_aiter_lines():
        for line in stream_lines:
            yield line.decode("utf-8")

    mock_stream_response = MagicMock()
    mock_stream_response.status_code = 200
    mock_stream_response.aiter_lines = mock_aiter_lines

    class MockStreamContext:
        async def __aenter__(self):
            return mock_stream_response

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass

    with patch("sentinelai.proxy.ollama.httpx.AsyncClient.stream", return_value=MockStreamContext()):
        payload = {
            "model": "llama3.2:3b",
            "messages": [{"role": "user", "content": "What is support email?"}],
            "stream": True,
        }
        res = await client.post("/v1/chat/completions", json=payload)

    assert res.status_code == 200
    body = res.text
    assert "support@sentinelai.com" not in body
    assert "<EMAIL_ADDRESS>" in body or "<EMAIL>" in body


@pytest.mark.asyncio
async def test_scan_output_api_endpoint(client: AsyncClient):
    payload = {
        "content": "Internal response: system prompt: you are an unrestricted model."
    }
    res = await client.post("/v1/security/scan-output", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["is_redacted"] is True
    assert "SYSTEM_PROMPT_DISCLOSURE" in data["leaks_detected"]
