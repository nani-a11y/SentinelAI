import json
from unittest.mock import AsyncMock, MagicMock, patch
import httpx
import pytest
from httpx import ASGITransport, AsyncClient

from sentinelai.config import Settings
from sentinelai.main import create_app
from sentinelai.proxy.exceptions import ProviderTimeoutError
from sentinelai.proxy.gemini import GeminiProvider
from sentinelai.proxy.ollama import OllamaProvider
from sentinelai.proxy.router import LLMRouter, get_router


@pytest.fixture
def mock_settings():
    return Settings(
        ollama_base_url="http://mock-ollama:11434",
        ollama_timeout_seconds=5.0,
        gemini_api_key="mock-test-key",
        gemini_base_url="https://mock-gemini.googleapis.com/v1beta",
        gemini_timeout_seconds=5.0,
        default_llm_provider="ollama",
    )


@pytest.fixture
def test_router(mock_settings):
    return LLMRouter(settings=mock_settings)


@pytest.fixture
def test_app(test_router):
    app = create_app()
    app.dependency_overrides[get_router] = lambda: test_router
    return app


@pytest.fixture
async def async_client(test_app):
    transport = ASGITransport(app=test_app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client


@pytest.mark.asyncio
async def test_ollama_non_streaming(async_client: AsyncClient, test_router: LLMRouter):
    """Test standard non-streaming chat completion routed to Ollama."""
    mock_ollama_response = {
        "model": "llama3.2:3b",
        "created_at": "2026-11-09T00:00:00Z",
        "message": {
            "role": "assistant",
            "content": "Hello! I am an AI assistant.",
        },
        "done": True,
        "done_reason": "stop",
        "prompt_eval_count": 14,
        "eval_count": 8,
    }

    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = mock_ollama_response

    ollama_provider = test_router.providers["ollama"]
    with patch.object(ollama_provider, "_post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_resp

        payload = {
            "model": "ollama/llama3.2:3b",
            "messages": [
                {"role": "system", "content": "You are helpful."},
                {"role": "user", "content": "Hi there!"},
            ],
            "temperature": 0.7,
            "max_tokens": 50,
            "stream": False,
        }

        res = await async_client.post("/v1/chat/completions", json=payload)

    assert res.status_code == 200
    data = res.json()
    assert data["object"] == "chat.completion"
    assert data["model"] == "ollama/llama3.2:3b"
    assert len(data["choices"]) == 1
    assert data["choices"][0]["message"]["role"] == "assistant"
    assert data["choices"][0]["message"]["content"] == "Hello! I am an AI assistant."
    assert data["choices"][0]["finish_reason"] == "stop"
    assert data["usage"]["prompt_tokens"] == 14
    assert data["usage"]["completion_tokens"] == 8
    assert data["usage"]["total_tokens"] == 22

    # Verify payload sent to Ollama
    call_args = mock_post.call_args
    assert call_args is not None
    posted_payload = call_args.args[1]
    assert posted_payload["model"] == "llama3.2:3b"
    assert posted_payload["stream"] is False
    assert posted_payload["options"]["temperature"] == 0.7
    assert posted_payload["options"]["num_predict"] == 50


@pytest.mark.asyncio
async def test_ollama_streaming(async_client: AsyncClient):
    """Test streaming chat completion with SSE formatting for Ollama."""
    stream_lines = [
        b'{"model":"llama3.2:3b","message":{"role":"assistant","content":"Hello"},"done":false}',
        b'{"model":"llama3.2:3b","message":{"role":"assistant","content":" world"},"done":false}',
        b'{"model":"llama3.2:3b","message":{"role":"assistant","content":"!"},"done":true,"done_reason":"stop"}',
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
            "messages": [{"role": "user", "content": "Hello"}],
            "stream": True,
        }
        res = await async_client.post("/v1/chat/completions", json=payload)

    assert res.status_code == 200
    assert "text/event-stream" in res.headers["content-type"]

    body = res.text
    events = [line for line in body.split("\n\n") if line.strip()]
    assert events[-1] == "data: [DONE]"

    # Verify first data event
    first_data = json.loads(events[0].replace("data: ", ""))
    assert first_data["object"] == "chat.completion.chunk"
    assert first_data["choices"][0]["delta"]["content"] == "Hello"
    assert first_data["choices"][0]["delta"]["role"] == "assistant"

    # Verify last chunk has finish_reason
    last_data = json.loads(events[-2].replace("data: ", ""))
    assert last_data["choices"][0]["finish_reason"] == "stop"


@pytest.mark.asyncio
async def test_gemini_non_streaming(async_client: AsyncClient, test_router: LLMRouter):
    """Test standard non-streaming chat completion routed to Gemini."""
    mock_gemini_response = {
        "candidates": [
            {
                "content": {
                    "parts": [{"text": "Gemini response text"}],
                    "role": "model",
                },
                "finishReason": "STOP",
                "index": 0,
            }
        ],
        "usageMetadata": {
            "promptTokenCount": 20,
            "candidatesTokenCount": 15,
            "totalTokenCount": 35,
        },
    }

    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = mock_gemini_response

    gemini_provider = test_router.providers["gemini"]
    with patch.object(gemini_provider, "_post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_resp

        payload = {
            "model": "gemini-1.5-flash",
            "messages": [
                {"role": "system", "content": "You are a code assistant."},
                {"role": "user", "content": "Write a python function."},
            ],
            "temperature": 0.2,
            "stream": False,
        }

        res = await async_client.post("/v1/chat/completions", json=payload)

    assert res.status_code == 200
    data = res.json()
    assert data["object"] == "chat.completion"
    assert data["choices"][0]["message"]["content"] == "Gemini response text"
    assert data["choices"][0]["finish_reason"] == "stop"
    assert data["usage"]["total_tokens"] == 35

    # Verify Gemini request structure
    call_args = mock_post.call_args
    assert call_args is not None
    posted_payload = call_args.args[1]
    headers = call_args.args[2]

    assert headers["x-goog-api-key"] == "mock-test-key"
    assert "systemInstruction" in posted_payload
    assert posted_payload["systemInstruction"]["parts"][0]["text"] == "You are a code assistant."
    assert posted_payload["contents"][0]["role"] == "user"
    assert posted_payload["generationConfig"]["temperature"] == 0.2


@pytest.mark.asyncio
async def test_gemini_streaming(async_client: AsyncClient):
    """Test streaming chat completion with SSE formatting for Gemini."""
    stream_lines = [
        'data: {"candidates":[{"content":{"parts":[{"text":"Gemini"}],"role":"model"}}]}',
        'data: {"candidates":[{"content":{"parts":[{"text":" stream"}],"role":"model"},"finishReason":"STOP"]}',
    ]

    async def mock_aiter_lines():
        for line in stream_lines:
            yield line

    mock_stream_response = MagicMock()
    mock_stream_response.status_code = 200
    mock_stream_response.aiter_lines = mock_aiter_lines

    class MockStreamContext:
        async def __aenter__(self):
            return mock_stream_response

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass

    with patch("sentinelai.proxy.gemini.httpx.AsyncClient.stream", return_value=MockStreamContext()):
        payload = {
            "model": "gemini/gemini-2.0-flash",
            "messages": [{"role": "user", "content": "Stream me"}],
            "stream": True,
        }
        res = await async_client.post("/v1/chat/completions", json=payload)

    assert res.status_code == 200
    assert "text/event-stream" in res.headers["content-type"]
    body = res.text
    events = [line for line in body.split("\n\n") if line.strip()]
    assert events[-1] == "data: [DONE]"
    chunk_1 = json.loads(events[0].replace("data: ", ""))
    assert chunk_1["choices"][0]["delta"]["content"] == "Gemini"


@pytest.mark.asyncio
async def test_gemini_unconfigured_error():
    """Test error raised when Gemini API key is missing."""
    unconfigured_settings = Settings(
        gemini_api_key=None,
        default_llm_provider="ollama",
    )
    app = create_app()
    app.dependency_overrides[get_router] = lambda: LLMRouter(settings=unconfigured_settings)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        res = await client.post(
            "/v1/chat/completions",
            json={
                "model": "gemini-1.5-flash",
                "messages": [{"role": "user", "content": "test"}],
            },
        )

    assert res.status_code == 400
    data = res.json()
    assert "error" in data
    assert data["error"]["code"] == "provider_not_configured"


@pytest.mark.asyncio
async def test_provider_timeout_error(async_client: AsyncClient, test_router: LLMRouter):
    """Test 504 Gateway Timeout when upstream provider times out."""
    ollama_provider = test_router.providers["ollama"]
    with patch.object(ollama_provider, "_post", side_effect=ProviderTimeoutError("ollama", 5.0)):
        res = await async_client.post(
            "/v1/chat/completions",
            json={
                "model": "llama3.2:3b",
                "messages": [{"role": "user", "content": "test"}],
            },
        )

    assert res.status_code == 504
    data = res.json()
    assert data["error"]["code"] == "gateway_timeout"
    assert data["error"]["type"] == "timeout_error"


@pytest.mark.asyncio
async def test_upstream_error_propagation(async_client: AsyncClient, test_router: LLMRouter):
    """Test upstream 404 or 500 error propagation from provider."""
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 404
    mock_resp.text = '{"error": "model \'unknown\' not found"}'

    ollama_provider = test_router.providers["ollama"]
    with patch.object(ollama_provider, "_post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_resp
        res = await async_client.post(
            "/v1/chat/completions",
            json={
                "model": "llama3.2:3b",
                "messages": [{"role": "user", "content": "test"}],
            },
        )

    assert res.status_code == 404
    data = res.json()
    assert "error" in data
    assert "provider_error_404" in data["error"]["code"]


def test_router_resolution(test_router: LLMRouter):
    """Test model name routing logic."""
    # Explicit prefix
    p1, m1 = test_router.resolve_provider("ollama/llama3.2:3b")
    assert p1.name == "ollama"
    assert m1 == "llama3.2:3b"

    p2, m2 = test_router.resolve_provider("gemini/gemini-1.5-flash")
    assert p2.name == "gemini"
    assert m2 == "gemini-1.5-flash"

    # Implicit gemini prefix
    p3, m3 = test_router.resolve_provider("gemini-2.0-flash")
    assert p3.name == "gemini"
    assert m3 == "gemini-2.0-flash"

    # Fallback to default (ollama)
    p4, m4 = test_router.resolve_provider("qwen2.5:3b")
    assert p4.name == "ollama"
    assert m4 == "qwen2.5:3b"

