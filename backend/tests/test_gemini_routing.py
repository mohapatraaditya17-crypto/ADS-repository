import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
from unittest.mock import patch, MagicMock
from app.config import settings
from app.agents.llm import get_agent_llm_config, call_llm_stream, _call_gemini_stream
from app.rag.embeddings import get_embeddings, get_gemini_embeddings

def test_agent_routing_resolution():
    """Verify that agent names route to correct provider and model based on config."""
    # Temporarily set configuration
    original_heavy_prov = settings.LLM_PROVIDER_HEAVY
    original_heavy_mod = settings.LLM_MODEL_HEAVY
    original_light_prov = settings.LLM_PROVIDER_LIGHT
    original_light_mod = settings.LLM_MODEL_LIGHT
    original_default_prov = settings.LLM_PROVIDER
    original_default_mod = settings.LLM_MODEL

    settings.LLM_PROVIDER = "mock"
    settings.LLM_MODEL = "mock-model"
    settings.LLM_PROVIDER_HEAVY = "gemini"
    settings.LLM_MODEL_HEAVY = "gemini-2.0-flash"
    settings.LLM_PROVIDER_LIGHT = "ollama"
    settings.LLM_MODEL_LIGHT = "llama3.1"

    try:
        # Orchestrator is a heavy agent -> should route to gemini
        provider, model = get_agent_llm_config("orchestrator")
        assert provider == "gemini"
        assert model == "gemini-2.0-flash"

        # Threat hunter is a heavy agent -> should route to gemini
        provider, model = get_agent_llm_config("threat_hunter")
        assert provider == "gemini"
        assert model == "gemini-2.0-flash"

        # Policy Analyst is heavy -> gemini
        provider, model = get_agent_llm_config("policy_analyst")
        assert provider == "gemini"
        assert model == "gemini-2.0-flash"

        # Report Generator is a light agent -> should route to ollama
        provider, model = get_agent_llm_config("report_generator")
        assert provider == "ollama"
        assert model == "llama3.1"

        # Audit Analyst is a light agent -> should route to ollama
        provider, model = get_agent_llm_config("audit_analyst")
        assert provider == "ollama"
        assert model == "llama3.1"

        # Stack trace fallback testing
        # When agent_name is None, it should inspect the call stack.
        # Since this test function is not in the agent files list, it will fallback
        # to the global configuration default.
        provider, model = get_agent_llm_config(None)
        assert provider == "mock"
        assert model == "mock-model"

    finally:
        settings.LLM_PROVIDER_HEAVY = original_heavy_prov
        settings.LLM_MODEL_HEAVY = original_heavy_mod
        settings.LLM_PROVIDER_LIGHT = original_light_prov
        settings.LLM_MODEL_LIGHT = original_light_mod
        settings.LLM_PROVIDER = original_default_prov
        settings.LLM_MODEL = original_default_mod


@patch("requests.post")
def test_gemini_stream_request_structure(mock_post):
    """Verify that the Gemini REST request payload and URL structure are constructed correctly."""
    # Set mock key
    original_gemini_key = settings.GEMINI_API_KEY
    settings.GEMINI_API_KEY = "test-gemini-key-123"

    try:
        # Mock successful stream response (using generator simulation)
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.iter_lines.return_value = [
            b'data: {"candidates": [{"content": {"parts": [{"text": "Hello"}]}}]}',
            b'data: {"candidates": [{"content": {"parts": [{"text": " World"}]}}]}'
        ]
        mock_post.return_value = mock_response

        # Execute Gemini stream
        system_prompt = "You are a copilot."
        user_prompt = "Check hosts."
        chat_history = [{"role": "user", "content": "hi"}, {"role": "assistant", "content": "hello"}]
        
        stream = _call_gemini_stream(system_prompt, user_prompt, chat_history, "gemini-2.0-flash")
        response_text = "".join(list(stream))

        # Assertions
        assert response_text == "Hello World"
        mock_post.assert_called_once()
        
        # Verify URL parameters
        called_url = mock_post.call_args[0][0]
        assert "models/gemini-2.0-flash:streamGenerateContent" in called_url
        assert "key=test-gemini-key-123" in called_url
        assert "alt=sse" in called_url

        # Verify request payload
        called_payload = mock_post.call_args[1]["json"]
        assert called_payload["systemInstruction"]["parts"][0]["text"] == system_prompt
        assert len(called_payload["contents"]) == 3  # 2 history messages + 1 current user prompt
        assert called_payload["contents"][0]["role"] == "user"
        assert called_payload["contents"][1]["role"] == "model"  # mapped from assistant
        assert called_payload["contents"][2]["role"] == "user"

    finally:
        settings.GEMINI_API_KEY = original_gemini_key


@patch("requests.post")
def test_gemini_embeddings_structure(mock_post):
    """Verify that Gemini batch embeddings request and response parsing works."""
    original_gemini_key = settings.GEMINI_API_KEY
    settings.GEMINI_API_KEY = "test-gemini-key-123"

    try:
        # Mock successful embeddings response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "embeddings": [
                {"values": [0.1, 0.2, 0.3]},
                {"values": [0.4, 0.5, 0.6]}
            ]
        }
        mock_post.return_value = mock_response

        texts = ["text1", "text2"]
        embeddings = get_gemini_embeddings(texts)

        # Assertions
        assert len(embeddings) == 2
        assert embeddings[0] == [0.1, 0.2, 0.3]
        assert embeddings[1] == [0.4, 0.5, 0.6]
        mock_post.assert_called_once()

        called_url = mock_post.call_args[0][0]
        assert "models/gemini-embedding-2:batchEmbedContents" in called_url
        assert "key=test-gemini-key-123" in called_url

        called_payload = mock_post.call_args[1]["json"]
        assert len(called_payload["requests"]) == 2
        assert called_payload["requests"][0]["model"] == "models/gemini-embedding-2"
        assert called_payload["requests"][0]["content"]["parts"][0]["text"] == "text1"

    finally:
        settings.GEMINI_API_KEY = original_gemini_key
