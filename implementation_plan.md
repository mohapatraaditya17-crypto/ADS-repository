# Modular RAG Architecture Redesign Proposal

This document outlines the proposed design to refactor and upgrade the Falcon AI Copilot RAG pipeline into an enterprise-grade modular search engine.

---

## 1. Objectives & Key Requirements

*   **Independent Collections**: Segment knowledge into independent logical vector categories:
    *   `falcon_docs` (Console UI documentation)
    *   `falconpy_docs` (Python SDK reference)
    *   `api_ref` (Falcon REST APIs)
    *   `mitre_attack` (MITRE tactics/techniques mapping)
    *   `threat_intel` (Intel threat actors & malware profiles)
    *   `threat_hunting` (FQL/CQL query methodologies)
    *   `playbooks` (Incident response playbook templates)
    *   `os_internals` (Windows and Linux system behaviors)
    *   `policies` (Prevention and Firewall rules)
    *   `runbooks` (Customer migration runbooks)
*   **Deterministic Query Routing**: Before queries are executed, route the request to the target collection based on deterministic keyword and regex markers.
*   **Hybrid Search Engine**: Combine dense vector similarity search (cosine distance of nomic-embed-text/gemini vectors) with sparse keyword queries (SQL FTS or LIKE patterns) to retrieve both contextual and exact-match content.
*   **Reranking (RRF)**: Implement Reciprocal Rank Fusion (RRF) to merge and prioritize rankings from dense and sparse search passes.
*   **Incremental Version Updates & Checksums**: Audit documents using SHA256 file hashes. Skip unchanged documents during index scans, and perform incremental deletes and updates on changed files.
*   **Enforced Source Citation**: Track document versions and file sources to return strict, verifiable grounding metadata to the reasoning agent.

---

## 2. Proposed Database Schema Upgrades

### Table: `document_metadata` [NEW]
Tracks file hashes and version states to enable incremental delta ingestion.
```sql
CREATE TABLE IF NOT EXISTS document_metadata (
    file_path TEXT PRIMARY KEY,
    file_hash TEXT NOT NULL,
    version TEXT NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### Table: `knowledge_chunks` [MODIFY]
Expand table to support explicit categorization, source paths, and confidence tracking.
```sql
CREATE TABLE IF NOT EXISTS knowledge_chunks (
    id SERIAL PRIMARY KEY, -- INTEGER PRIMARY KEY for SQLite
    content TEXT NOT NULL,
    embedding VECTOR(1536) NOT NULL, -- TEXT for SQLite
    metadata TEXT NOT NULL,
    collection VARCHAR(50) NOT NULL, -- Category partition index
    source_path TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

---

## 3. Modular Pipeline Implementation Details

### A. Semantic Chunking
*   Split documents by markdown structures (`#`, `##`, `###`) or logical paragraph boundaries (`\n\n`) instead of arbitrary character offsets.
*   Verify that code blocks, list items, and table structures are kept intact within single chunks where possible.

### B. Ingestion Checksum Auditing
1. For each scanned document in `data_dir`, generate its SHA256 checksum.
2. Query `document_metadata` to compare hashes.
3. If hashes match, skip ingestion of that file.
4. If hashes differ (or file is new):
   - Delete all existing records in `knowledge_chunks` where `source_path = file_path`.
   - Chunk, embed, and insert new segments.
   - Update `document_metadata` with the new hash.

### C. Intent-Driven Query Router
Deterministic classification checks in `retriever.py` to route queries before DB search:
*   `sdk`, `falconpy`, `ServiceClass`, `Uber class` ──> `falconpy_docs`
*   `GET /api`, `POST /api`, `endpoint` ──> `api_ref`
*   `tactic`, `technique`, `mitre`, `T1003` ──> `mitre_attack`
*   `actor`, `campaign`, `malware`, `intelligence` ──> `threat_intel`
*   `sigma`, `yara`, `splunk`, `logscale` ──> `threat_hunting`
*   `playbook`, `sop`, `incident response`, `triage` ──> `playbooks`
*   `registry`, `process`, `memory`, `kernel`, `lsass` ──> `os_internals`
*   `exclusion`, `prevention policy`, `firewall` ──> `policies`
*   `migration`, `raci`, `deployment tracker` ──> `runbooks`

### D. Hybrid Search & RRF Reranking
1. Perform a Dense Search: Similarity search returning top 15 results by cosine distance.
2. Perform a Sparse Search: Keyword text query (e.g. using full-text search) returning top 15 results.
3. Apply RRF scoring:
   $$RRF(d) = \sum_{m \in M} \frac{1}{60 + r_m(d)}$$
4. Sort by RRF score descending and take the top `limit` (e.g. top 5) documents.

---

## 4. Proposed Changes

### [MODIFY] [database.py](file:///c:/Users/us183046/OneDrive%20-%20Grant%20Thornton%20Advisors%20LLC/Desktop/Falcon%20LLM/backend/app/database.py)
* Add `document_metadata` table creation to `init_db`.
* Implement Hybrid Search and reciprocal rank fusion reranker within `similarity_search`.

### [MODIFY] [ingest.py](file:///c:/Users/us183046/OneDrive%20-%20Grant%20Thornton%20Advisors%20LLC/Desktop/Falcon%20LLM/backend/app/rag/ingest.py)
* Add SHA256 checksum calculation for each file.
* Check file hash state prior to parsing. Delete stale chunks and update database metadata on change.
* Upgrade chunking logic to support semantic paragraph splitting.

### [MODIFY] [retriever.py](file:///c:/Users/us183046/OneDrive%20-%20Grant%20Thornton%20Advisors%20LLC/Desktop/Falcon%20LLM/backend/app/rag/retriever.py)
* Add deterministic query routing function to detect target collections.
* Include similarity confidence score and grounding metadata in search result output format.

---

## 5. Verification Plan

### Automated Verification
*   Create a new test module `backend/tests/test_modular_rag.py` to:
    *   Verify deterministic routing rules return appropriate collection classes.
    *   Verify hybrid search queries combine vector similarity and text parameters correctly.
    *   Verify RRF scoring sorts items accurately.
    *   Verify that unchanged files are skipped during duplicate runs.

### Manual Verification
1. Run ingestion script twice in succession. Confirm that the second run takes $<0.5$ seconds due to checksum-based cache matching.
2. Run a query mapping to API definitions (e.g., `"GET /alerts/entities/alerts/v2"`). Verify that routing detects `api_ref` and grounds answers in API specs.
