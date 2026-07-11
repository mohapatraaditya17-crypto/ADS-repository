import sys
import os
import sqlite3
import json
import pytest
from typing import List

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.rag.retriever import route_query
import app.database as db

class MockConnectionWrapper:
    def __init__(self, conn):
        self._conn = conn
    def cursor(self, *args, **kwargs):
        return self._conn.cursor(*args, **kwargs)
    def execute(self, *args, **kwargs):
        return self._conn.execute(*args, **kwargs)
    def executemany(self, *args, **kwargs):
        return self._conn.executemany(*args, **kwargs)
    def commit(self, *args, **kwargs):
        return self._conn.commit(*args, **kwargs)
    def rollback(self, *args, **kwargs):
        return self._conn.rollback(*args, **kwargs)
    def close(self):
        pass
    def __enter__(self):
        return self
    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

def test_deterministic_query_routing():
    """Verify that search queries are routed to the correct database partitions."""
    assert route_query("How do I use the FalconPy Uber class?") == "falconpy_docs"
    assert route_query("what is the serviceclass definition?") == "falconpy_docs"
    
    assert route_query("GET /alerts/entities/alerts/v2 endpoint parameters") == "api_ref"
    assert route_query("API reference for Swagger") == "api_ref"
    
    assert route_query("Which techniques map to MITRE ATT&CK tactic execution?") == "mitre_attack"
    assert route_query("MITRE technique T1003 details") == "mitre_attack"
    
    assert route_query("Who is threat actor WICKED SPIDER?") == "threat_intel"
    assert route_query("Is there threat intel on malware EMOTET?") == "threat_intel"
    
    assert route_query("Provide splunk hunt query for lateral movement") == "threat_hunting"
    assert route_query("Is there a Sigma rule for registry run key additions?") == "threat_hunting"
    
    assert route_query("LSASS dumping triage playbook SOP") == "playbooks"
    assert route_query("LSASS dump investigation playbook") == "playbooks"
    
    assert route_query("registry key modification process internals") == "os_internals"
    assert route_query("LSASS memory structure kernel space") == "os_internals"
    
    assert route_query("how to set exclusion in prevention policy") == "policies"
    assert route_query("Windows sensor update firewall policies") == "policies"
    
    # Check default fallback
    assert route_query("general crowdstrike console interface search") == "falcon_docs"

def test_incremental_auditing_helpers(monkeypatch):
    """Verify database caching and hashing helpers run correctly."""
    # Force SQLite fallback connection to use a clean in-memory database for testing
    in_mem_db = sqlite3.connect(":memory:")
    wrapper = MockConnectionWrapper(in_mem_db)
    
    # Scaffolding schemas
    with in_mem_db:
        in_mem_db.execute("""
            CREATE TABLE IF NOT EXISTS document_metadata (
                file_path TEXT PRIMARY KEY,
                file_hash TEXT NOT NULL,
                version TEXT NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        in_mem_db.execute("""
            CREATE TABLE IF NOT EXISTS knowledge_chunks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                content TEXT NOT NULL,
                embedding TEXT NOT NULL,
                metadata TEXT NOT NULL,
                collection VARCHAR(50) NOT NULL,
                source_path TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        
    def mock_get_connection():
        return wrapper
        
    monkeypatch.setattr(db, "get_connection", mock_get_connection)
    monkeypatch.setattr(db, "is_sqlite", lambda: True)

    # Test metadata caching
    path = "C:/test/file.md"
    content_hash = "abc123hash"
    
    assert db.get_document_metadata(path) is None
    
    db.update_document_metadata(path, content_hash, "1.0")
    meta = db.get_document_metadata(path)
    assert meta is not None
    assert meta["file_hash"] == content_hash
    assert meta["version"] == "1.0"
    
    # Store mock chunk
    db.store_chunks([{
        "content": "Test content",
        "embedding": [0.1] * 1536,
        "metadata": {"category": "falconpy_docs", "source_path": path}
    }])
    
    cursor = in_mem_db.cursor()
    cursor.execute("SELECT count(*) FROM knowledge_chunks WHERE source_path = ?;", (path,))
    assert cursor.fetchone()[0] == 1
    
    # Test incremental wipe out chunk
    db.delete_document_chunks(path)
    cursor.execute("SELECT count(*) FROM knowledge_chunks WHERE source_path = ?;", (path,))
    assert cursor.fetchone()[0] == 0

def test_hybrid_search_and_rrf_reranking(monkeypatch):
    """Verify hybrid search returns RRF-merged and ranked vector chunks."""
    in_mem_db = sqlite3.connect(":memory:")
    wrapper = MockConnectionWrapper(in_mem_db)
    
    with in_mem_db:
        in_mem_db.execute("""
            CREATE TABLE IF NOT EXISTS knowledge_chunks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                content TEXT NOT NULL,
                embedding TEXT NOT NULL,
                metadata TEXT NOT NULL,
                collection VARCHAR(50) NOT NULL,
                source_path TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

    monkeypatch.setattr(db, "get_connection", lambda: wrapper)
    monkeypatch.setattr(db, "is_sqlite", lambda: True)

    # Store 3 mock chunks
    chunks = [
        {
            "content": "FalconPy ServiceClass parameters definition",
            "embedding": [0.9, 0.1, 0.0],
            "metadata": {"category": "falconpy_docs", "source_path": "file1.md"}
        },
        {
            "content": "Windows registry process execution internals",
            "embedding": [0.1, 0.9, 0.0],
            "metadata": {"category": "os_internals", "source_path": "file2.md"}
        },
        {
            "content": "FalconPy Uber class client usage instruction",
            "embedding": [0.8, 0.2, 0.0],
            "metadata": {"category": "falconpy_docs", "source_path": "file3.md"}
        }
    ]
    
    # For cosine similarity, pad the embedding to 1536 dimensions
    for c in chunks:
        padded = c["embedding"] + [0.0] * (1536 - len(c["embedding"]))
        c["embedding"] = padded
        
    db.store_chunks(chunks)

    # Test Hybrid Search with FTS and Dense match
    query_emb = [0.85, 0.15, 0.0] + [0.0] * 1533
    
    # Search with keyword "FalconPy"
    results = db.hybrid_search(
        query_text="FalconPy",
        query_embedding=query_emb,
        limit=5,
        collection_filter="falconpy_docs"
    )
    
    assert len(results) == 2
    assert "ServiceClass" in results[0]["content"]
    assert results[0]["collection"] == "falconpy_docs"
    assert results[0]["confidence"] > 0.8
