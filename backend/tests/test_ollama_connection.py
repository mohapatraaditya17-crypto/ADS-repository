import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
import requests
from app.config import settings
from app.rag.embeddings import get_ollama_embeddings
from app.agents.llm import call_llm_stream

def test_config_has_ollama_base_url():
    """Verify that the config has OLLAMA_BASE_URL parsed."""
    assert hasattr(settings, "OLLAMA_BASE_URL")
    assert settings.OLLAMA_BASE_URL.startswith("http")

def test_ollama_service_reachable():
    """Verify that the local Ollama service is reachable and responsive."""
    try:
        url = f"{settings.OLLAMA_BASE_URL.rstrip('/')}/api/tags"
        res = requests.get(url, timeout=5)
        assert res.status_code == 200
        data = res.json()
        assert "models" in data
        
        # Verify that we have some models installed
        model_names = [m["name"] for m in data["models"]]
        print(f"Installed models in Ollama: {model_names}")
    except requests.exceptions.ConnectionError:
        pytest.fail(f"Could not connect to Ollama at {settings.OLLAMA_BASE_URL}. Ensure Ollama is running.")

def test_ollama_embeddings_generation():
    """Verify that Ollama embedding generation works and does not fall back to mock when provider is ollama."""
    # Temporarily set provider to ollama if not already set
    original_provider = settings.LLM_PROVIDER
    settings.LLM_PROVIDER = "ollama"
    
    try:
        texts = ["Verify that Ollama embedding calculation is successful."]
        embeddings = get_ollama_embeddings(texts)
        
        # Verify result shape and content
        assert len(embeddings) == 1
        assert len(embeddings[0]) == 768  # nomic-embed-text embedding size is 768
        assert all(isinstance(x, float) for x in embeddings[0])
    finally:
        settings.LLM_PROVIDER = original_provider

def test_ollama_stream_generation():
    """Verify that Ollama LLM call returns tokens and responds."""
    # Temporarily set model settings
    original_provider = settings.LLM_PROVIDER
    original_model = settings.LLM_MODEL
    settings.LLM_PROVIDER = "ollama"
    
    # Query Ollama to see what models are actually installed and use one
    try:
        url = f"{settings.OLLAMA_BASE_URL.rstrip('/')}/api/tags"
        res = requests.get(url, timeout=5)
        if res.status_code == 200:
            models = res.json().get("models", [])
            installed_names = [m["name"] for m in models]
            # Get text models (filtering out embed models)
            text_models = [name for name in installed_names if "embed" not in name.lower()]
            if text_models:
                settings.LLM_MODEL = text_models[0]
            else:
                settings.LLM_MODEL = "llama3"
        else:
            settings.LLM_MODEL = "llama3"
    except Exception:
        settings.LLM_MODEL = "llama3"
    
    try:
        system_prompt = "You are a helpful assistant."
        user_prompt = "Respond with exactly the word: SUCCESS"
        
        stream = call_llm_stream(system_prompt, user_prompt, chat_history=[])
        response_text = "".join(list(stream))
        
        # Check that we got a valid response (and not the mock or system error message)
        assert len(response_text) > 0
        assert "System Error:" not in response_text
        assert "SUCCESS" in response_text.upper()
    finally:
        settings.LLM_PROVIDER = original_provider
        settings.LLM_MODEL = original_model
