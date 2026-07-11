import logging
import random
import requests
from typing import List
from app.config import settings

logger = logging.getLogger("embeddings")

def get_openai_embeddings(texts: List[str]) -> List[List[float]]:
    """Calculates embeddings using OpenAI API directly."""
    try:
        url = "https://api.openai.com/v1/embeddings"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {settings.OPENAI_API_KEY}"
        }
        payload = {
            "input": texts,
            "model": "text-embedding-3-small"
        }
        res = requests.post(url, json=payload, headers=headers, timeout=15)
        res.raise_for_status()
        data = res.json()
        return [item["embedding"] for item in data["data"]]
    except Exception as e:
        logger.error(f"OpenAI embedding generation failed: {e}. Falling back to mock embeddings.")
        return get_mock_embeddings(texts)

def get_ollama_embeddings(texts: List[str]) -> List[List[float]]:
    """Calculates embeddings using local Ollama service with internal batching to prevent timeouts."""
    try:
        base_url = settings.OLLAMA_BASE_URL.rstrip('/')
        
        # Docker fallback bridge if OLLAMA_BASE_URL points to localhost/127.0.0.1 but DB is inside container
        is_localhost = any(lh in base_url for lh in ["localhost", "127.0.0.1"])
        if is_localhost and settings.DB_HOST == "db":
            base_url = "http://host.docker.internal:11434"
            
        url = f"{base_url}/api/embed"
        
        all_embeddings = []
        # Process in smaller batches of 10 to avoid Ollama timeout
        batch_size = 10
        for i in range(0, len(texts), batch_size):
            batch = texts[i : i + batch_size]
            payload = {
                "model": "nomic-embed-text",
                "input": batch
            }
            res = requests.post(url, json=payload, timeout=60)
            res.raise_for_status()
            data = res.json()
            all_embeddings.extend(data["embeddings"])
            
        return all_embeddings
    except Exception as e:
        logger.error(f"Ollama embedding generation failed at '{url}': {e}. Falling back to mock embeddings.")
        return get_mock_embeddings(texts)

def get_mock_embeddings(texts: List[str]) -> List[List[float]]:
    """Generates deterministic mock embeddings for testing and debug mode."""
    results = []
    for text in texts:
        # Seed generator based on text content hash so the vector is deterministic
        state = random.Random(hash(text))
        vector = [state.uniform(-1, 1) for _ in range(settings.EMBEDDING_DIM)]
        
        # Normalize the vector to unit length (length = 1.0) for proper cosine calculation
        length = sum(x*x for x in vector) ** 0.5
        normalized_vector = [x / length for x in vector]
        results.append(normalized_vector)
    return results

def get_gemini_embeddings(texts: List[str]) -> List[List[float]]:
    """Calculates embeddings using Gemini API (gemini-embedding-2) with internal batching if needed."""
    if not settings.GEMINI_API_KEY or settings.GEMINI_API_KEY == "mock-key":
        logger.error("Gemini API key is not configured for embeddings. Falling back to mock embeddings.")
        return get_mock_embeddings(texts)
    try:
        # Google Gemini embeddings endpoint for batch requests
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-embedding-2:batchEmbedContents?key={settings.GEMINI_API_KEY}"
        
        # Batch requests
        requests_payload = []
        for text in texts:
            requests_payload.append({
                "model": "models/gemini-embedding-2",
                "content": {
                    "parts": [{"text": text}]
                }
            })
        payload = {"requests": requests_payload}
        
        res = requests.post(url, json=payload, headers={"Content-Type": "application/json"}, timeout=15)
        res.raise_for_status()
        data = res.json()
        return [item["values"] for item in data["embeddings"]]
    except Exception as e:
        logger.error(f"Gemini embedding generation failed: {e}. Falling back to mock embeddings.")
        return get_mock_embeddings(texts)

def get_embeddings(texts: List[str]) -> List[List[float]]:
    """
    Interface function to calculate embeddings for a list of strings.
    Automatically routes based on settings.LLM_PROVIDER configuration.
    """
    if not texts:
        return []
        
    provider = settings.LLM_PROVIDER.lower()
    
    if provider == "openai":
        return get_openai_embeddings(texts)
    elif provider == "gemini":
        return get_gemini_embeddings(texts)
    elif provider == "ollama":
        return get_ollama_embeddings(texts)
    else:
        # Default mock mode
        return get_mock_embeddings(texts)

def get_single_embedding(text: str) -> List[float]:
    """Calculates embedding for a single text string."""
    return get_embeddings([text])[0]
