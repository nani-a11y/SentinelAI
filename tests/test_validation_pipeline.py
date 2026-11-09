import json
from unittest.mock import AsyncMock, MagicMock, patch
import httpx
import pytest
from httpx import ASGITransport, AsyncClient

from sentinelai.main import app
from sentinelai.security.output_guard import OutputGuard, StreamingOutputSanitizer


@pytest.mark.asyncio
async def test_full_pipeline_input_to_output():
    """Verify complete end-to-end flow: input validation -> authorized tool -> provider -> output sanitization."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "model": "llama3.2:3b",
            "message": {
                "role": "assistant",
                "content": "Contact support at admin@sentinelai.com for medication advice.",
            },
            "done": True,
            "prompt_eval_count": 10,
            "eval_count": 10,
        }

        with patch("sentinelai.proxy.ollama.OllamaProvider._post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_resp
            payload = {
                "model": "llama3.2:3b",
                "messages": [
                    {"role": "user", "content": "How do I use the weather tool safely?"}
                ],
                "tools": [{"name": "get_weather", "type": "function"}],
                "stream": False,
            }
            resp = await client.post("/v1/chat/completions", json=payload)
            assert resp.status_code == 200
            data = resp.json()
            content = data["choices"][0]["message"]["content"]

            # Output guard redacted PII
            assert "admin@sentinelai.com" not in content
            assert "<EMAIL_ADDRESS>" in content
            # Health safety added medical disclaimer because 'medication' was mentioned
            assert "MEDICAL DISCLAIMER:" in content


def test_streaming_chunk_boundary_secret_leak_blocked():
    """Verify that a critical secret split across chunk boundaries is caught by the accumulated stream sanitizer."""
    guard = OutputGuard()
    sanitizer = StreamingOutputSanitizer(output_guard=guard)

    # Secret: sk-proj-1234567890abcdef1234567890abcdef
    # Split across 3 separate chunk deliveries
    c1 = sanitizer.process_chunk("Here is your key: sk-proj-12345")
    assert sanitizer.blocked is False
    assert c1 is not None

    c2 = sanitizer.process_chunk("67890abcdef1234")
    assert sanitizer.blocked is False

    c3 = sanitizer.process_chunk("567890abcdef.")
    # On the 3rd chunk, accumulated text forms the full critical OpenAI secret
    assert sanitizer.blocked is True
    assert "BLOCKED BY SENTINELAI" in (c3 or "")


def test_false_positive_benign_security_research():
    """Verify that educational and defensive security queries are not falsely blocked."""
    from sentinelai.security.engine import SecurityEngine
    engine = SecurityEngine()

    benign_security_queries = [
        "What is the difference between prompt injection and SQL injection?",
        "Explain how jailbreaks work and how modern LLMs defend against them.",
        "How do developers sanitize inputs to prevent system prompt extraction?",
        "What are the best practices for detecting exposed API keys in git repositories?",
    ]

    for query in benign_security_queries:
        assessment = engine.evaluate_text(query)
        assert assessment.is_blocked is False, f"Falsely blocked benign query: '{query}'"


@pytest.mark.asyncio
async def test_unauthorized_tool_blocked_before_provider_execution():
    """Verify that unauthorized tools are rejected with 403 before any provider call is made."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        with patch("sentinelai.proxy.ollama.OllamaProvider._post", new_callable=AsyncMock) as mock_post:
            payload = {
                "model": "llama3.2:3b",
                "messages": [{"role": "user", "content": "Execute bash command"}],
                "tools": [{"name": "execute_bash", "type": "function"}],
                "stream": False,
            }
            resp = await client.post("/v1/chat/completions", json=payload)
            assert resp.status_code == 403
            data = resp.json()
            assert data["error"]["code"] == "unauthorized_tool_call"
            # Verify provider was never contacted
            mock_post.assert_not_called()
