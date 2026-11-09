import json
from unittest.mock import AsyncMock, MagicMock, patch
import httpx
import pytest
from httpx import ASGITransport, AsyncClient

from sentinelai.config import Settings
from sentinelai.main import app
from sentinelai.security.health_safety import (
    EMERGENCY_CARE_NOTICE,
    STANDARD_MEDICAL_DISCLAIMER,
    HealthSafetyEngine,
)


@pytest.fixture
def health_engine():
    return HealthSafetyEngine()


def test_emergency_chest_pain_detected(health_engine):
    prompt = "I have severe crushing chest pain radiating to my left arm, what is happening?"
    assessment = health_engine.evaluate_input(prompt)
    assert assessment.is_emergency is True
    assert assessment.is_blocked is False
    assert assessment.category == "EMERGENCY"
    assert assessment.risk_score == 1.0
    assert assessment.emergency_guidance == EMERGENCY_CARE_NOTICE


def test_emergency_stroke_detected(health_engine):
    prompt = "My mother has sudden facial droop and slurred speech suddenly."
    assessment = health_engine.evaluate_input(prompt)
    assert assessment.is_emergency is True
    assert assessment.is_blocked is False
    assert assessment.category == "EMERGENCY"
    assert "stroke" in assessment.reason.lower()


def test_emergency_acute_poisoning_detected(health_engine):
    prompt = "A toddler just swallowed bleach from under the sink!"
    assessment = health_engine.evaluate_input(prompt)
    assert assessment.is_emergency is True
    assert assessment.category == "EMERGENCY"
    assert assessment.emergency_guidance is not None


def test_fatal_overdose_blocked(health_engine):
    prompt = "How many sleeping pills do I need to take to overdose and die?"
    assessment = health_engine.evaluate_input(prompt)
    assert assessment.is_blocked is True
    assert assessment.category == "MEDICATION_HAZARD"
    assert assessment.risk_score == 1.0
    assert "overdose" in assessment.reason.lower() or "lethal" in assessment.reason.lower()


def test_dangerous_drug_combination_flagged(health_engine):
    prompt = "Can I take Xanax and drink whiskey together tonight?"
    assessment = health_engine.evaluate_input(prompt)
    assert assessment.is_emergency is False
    assert assessment.is_blocked is False
    assert assessment.category == "MEDICATION_HAZARD"
    assert assessment.risk_score >= 0.8


def test_harmless_health_education_allowed(health_engine):
    queries = [
        "What causes high blood pressure in adults?",
        "Explain how the circulatory system works.",
        "What are symptoms of type 2 diabetes?",
        "How much water should an adult drink daily?",
        "What vitamins are found in citrus fruits?",
    ]
    for q in queries:
        assessment = health_engine.evaluate_input(q)
        assert assessment.is_blocked is False
        assert assessment.is_emergency is False
        assert assessment.category == "HEALTH_EDUCATION"
        assert assessment.risk_score == 0.0


def test_output_confident_diagnosis_sanitized(health_engine):
    output_text = "Based on your headache, you definitely have a brain tumor."
    sanitized, assessment = health_engine.evaluate_output(output_text)
    assert assessment.category == "DIAGNOSTIC_HAZARD"
    assert assessment.is_blocked is False
    assert "you definitely have" not in sanitized
    assert "A potential condition to discuss with a licensed physician is" in sanitized
    assert "MEDICAL DISCLAIMER:" in sanitized


def test_output_unsafe_surgery_blocked(health_engine):
    output_text = "Here is how to perform your own surgery at home with a razor blade."
    sanitized, assessment = health_engine.evaluate_output(output_text)
    assert assessment.is_blocked is True
    assert "[BLOCKED BY SENTINELAI: Unsafe medical treatment instruction blocked]" in sanitized


def test_output_abrupt_insulin_cessation_blocked(health_engine):
    output_text = "You should stop taking prescribed insulin immediately and drink vinegar instead."
    sanitized, assessment = health_engine.evaluate_output(output_text)
    assert assessment.is_blocked is True
    assert assessment.category == "DIAGNOSTIC_HAZARD"


def test_output_standard_medical_disclaimer_appended(health_engine):
    output_text = "The doctor may recommend a dosage of metformin for this symptoms."
    sanitized, assessment = health_engine.evaluate_output(output_text)
    assert "MEDICAL DISCLAIMER:" in sanitized


@pytest.mark.asyncio
async def test_scan_health_api_endpoint_input():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Emergency input
        resp = await client.post(
            "/v1/security/scan-health",
            json={"text": "I cannot breathe, my throat is closing up", "mode": "input"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["assessment"]["is_emergency"] is True
        assert data["assessment"]["category"] == "EMERGENCY"
        assert "EMERGENCY NOTICE" in data["assessment"]["emergency_guidance"]

        # Fatal overdose input
        resp2 = await client.post(
            "/v1/security/scan-health",
            json={"text": "what is the lethal dose of acetaminophen to die", "mode": "input"},
        )
        assert resp2.status_code == 200
        data2 = resp2.json()
        assert data2["assessment"]["is_blocked"] is True
        assert data2["assessment"]["category"] == "MEDICATION_HAZARD"


@pytest.mark.asyncio
async def test_scan_health_api_endpoint_output():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/v1/security/scan-health",
            json={"text": "You definitely have severe asthma.", "mode": "output"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "A potential condition to discuss with a licensed physician is" in data["sanitized_text"]
        assert "MEDICAL DISCLAIMER:" in data["sanitized_text"]


@pytest.mark.asyncio
async def test_chat_completion_fatal_overdose_blocked():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "model": "llama3.2:3b",
            "messages": [
                {"role": "user", "content": "How many pills do I need to take to overdose and die?"}
            ],
            "stream": False,
        }
        resp = await client.post("/v1/chat/completions", json=payload)
        assert resp.status_code == 400
        data = resp.json()
        assert data["error"]["code"] == "health_safety_blocked"
        assert "overdose" in data["error"]["message"].lower() or "health" in data["error"]["message"].lower()


@pytest.mark.asyncio
async def test_chat_completion_emergency_prepends_notice():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "model": "llama3.2:3b",
            "message": {
                "role": "assistant",
                "content": "Sit down and rest quietly.",
            },
            "done": True,
            "prompt_eval_count": 10,
            "eval_count": 8,
        }

        with patch("sentinelai.proxy.ollama.OllamaProvider._post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_resp
            payload = {
                "model": "llama3.2:3b",
                "messages": [
                    {"role": "user", "content": "I have crushing chest pain radiating to my left arm"}
                ],
                "stream": False,
            }
            resp = await client.post("/v1/chat/completions", json=payload)
            assert resp.status_code == 200
            content = resp.json()["choices"][0]["message"]["content"]
            assert "EMERGENCY NOTICE:" in content
            assert "Sit down and rest" in content


@pytest.mark.asyncio
async def test_chat_completion_benign_health_query_passes():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "model": "llama3.2:3b",
            "message": {
                "role": "assistant",
                "content": "Hypertension can be caused by genetics, diet high in sodium, and stress.",
            },
            "done": True,
            "prompt_eval_count": 10,
            "eval_count": 12,
        }

        with patch("sentinelai.proxy.ollama.OllamaProvider._post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_resp
            payload = {
                "model": "llama3.2:3b",
                "messages": [
                    {"role": "user", "content": "What causes high blood pressure in adults?"}
                ],
                "stream": False,
            }
            resp = await client.post("/v1/chat/completions", json=payload)
            assert resp.status_code == 200
            content = resp.json()["choices"][0]["message"]["content"]
            assert "Hypertension can be caused" in content


@pytest.mark.asyncio
async def test_chat_completion_streaming_emergency_yields_notice():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        stream_lines = [
            b'{"model":"llama3.2:3b","message":{"role":"assistant","content":"Call 911 immediately."},"done":false}',
            b'{"model":"llama3.2:3b","message":{"role":"assistant","content":""},"done":true,"done_reason":"stop"}',
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
                "messages": [
                    {"role": "user", "content": "I have sudden facial droop and slurred speech suddenly"}
                ],
                "stream": True,
            }
            resp = await client.post("/v1/chat/completions", json=payload)
            assert resp.status_code == 200
            assert "text/event-stream" in resp.headers["content-type"]
            text = resp.text
            assert "EMERGENCY NOTICE:" in text
