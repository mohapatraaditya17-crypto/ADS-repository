import time
import logging
import json
import sqlite3
import psycopg2
from psycopg2.extras import RealDictCursor, Json as PGJson
from pgvector.psycopg2 import register_vector
from app.config import settings
from typing import List, Dict, Any, Optional

logger = logging.getLogger("database")

# Dynamic check for SQLite vs PostgreSQL
_use_sqlite = None

def is_sqlite() -> bool:
    global _use_sqlite
    if _use_sqlite is None:
        try:
            # Short connection test to see if PostgreSQL is available
            conn = psycopg2.connect(
                host=settings.DB_HOST,
                port=settings.DB_PORT,
                database=settings.DB_NAME,
                user=settings.DB_USER,
                password=settings.DB_PASSWORD,
                connect_timeout=2
            )
            conn.close()
            _use_sqlite = False
            logger.info("Database engine: PostgreSQL (pgvector)")
        except Exception:
            _use_sqlite = True
            logger.warning("Database engine: Falling back to local SQLite (PostgreSQL not reachable)")
    return _use_sqlite

def dot_product(v1, v2):
    return sum(x * y for x, y in zip(v1, v2))

def magnitude(v):
    return sum(x * x for x in v) ** 0.5

def cosine_similarity(v1, v2):
    m1 = magnitude(v1)
    m2 = magnitude(v2)
    if m1 == 0 or m2 == 0:
        return 0.0
    return dot_product(v1, v2) / (m1 * m2)

def get_connection(retries: int = 5, delay: float = 2.0):
    """
    Returns a connection to the database.
    If PostgreSQL is unreachable, falls back to SQLite.
    """
    if is_sqlite():
        return sqlite3.connect("falcon_copilot.db")
        
    conn = None
    for i in range(retries):
        try:
            conn = psycopg2.connect(
                host=settings.DB_HOST,
                port=settings.DB_PORT,
                database=settings.DB_NAME,
                user=settings.DB_USER,
                password=settings.DB_PASSWORD,
            )
            register_vector(conn)
            return conn
        except psycopg2.OperationalError as e:
            logger.warning(f"Database connection attempt {i+1}/{retries} failed. Retrying in {delay}s... Error: {e}")
            time.sleep(delay)
    
    logger.error("Could not connect to database after all retries.")
    raise ConnectionError("Failed to connect to PostgreSQL database.")

def init_db():
    """
    Initializes document tracking tables, pgvector extension, and fallback SQLite configurations.
    """
    if is_sqlite():
        conn = get_connection()
        try:
            with conn:
                # 1. Document checksum and version metadata tracker
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS document_metadata (
                        file_path TEXT PRIMARY KEY,
                        file_hash TEXT NOT NULL,
                        version TEXT NOT NULL,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                """)
                # 2. Vector chunks table updated with collection routing and file source columns
                conn.execute("""
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
                logger.info("Local SQLite knowledge tables initialized successfully.")
        except Exception as e:
            logger.error(f"Error initializing SQLite: {e}")
            raise e
        finally:
            conn.close()
        return

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("CREATE EXTENSION IF NOT EXISTS vector;")
            conn.commit()
            logger.info("pgvector extension confirmed active.")

            cur.execute("""
                CREATE TABLE IF NOT EXISTS document_metadata (
                    file_path TEXT PRIMARY KEY,
                    file_hash TEXT NOT NULL,
                    version TEXT NOT NULL,
                    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                );
            """)
            conn.commit()

            cur.execute(f"""
                CREATE TABLE IF NOT EXISTS knowledge_chunks (
                    id SERIAL PRIMARY KEY,
                    content TEXT NOT NULL,
                    embedding VECTOR({settings.EMBEDDING_DIM}) NOT NULL,
                    metadata JSONB NOT NULL,
                    collection VARCHAR(50) NOT NULL,
                    source_path TEXT NOT NULL,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                );
            """)
            conn.commit()
            
            cur.execute("""
                CREATE INDEX IF NOT EXISTS knowledge_chunks_embedding_idx 
                ON knowledge_chunks USING hnsw (embedding vector_cosine_ops);
            """)
            conn.commit()
            
            cur.execute("""
                CREATE INDEX IF NOT EXISTS knowledge_chunks_metadata_idx 
                ON knowledge_chunks USING gin (metadata);
            """)
            conn.commit()
            
            logger.info("Knowledge tables and vector indexes initialized successfully.")
    except Exception as e:
        conn.rollback()
        logger.error(f"Error initializing database: {str(e)}")
        raise e
    finally:
        conn.close()

def get_document_metadata(file_path: str) -> Optional[Dict[str, Any]]:
    """Retrieves stored file checksum hash and version metadata."""
    if is_sqlite():
        conn = get_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT file_hash, version FROM document_metadata WHERE file_path = ?;", (file_path,))
            row = cur.fetchone()
            if row:
                return {"file_hash": row[0], "version": row[1]}
        except Exception as e:
            logger.error(f"Error reading document metadata: {e}")
        finally:
            conn.close()
    else:
        conn = get_connection()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT file_hash, version FROM document_metadata WHERE file_path = %s;", (file_path,))
                row = cur.fetchone()
                if row:
                    return {"file_hash": row[0], "version": row[1]}
        except Exception as e:
            logger.error(f"Error reading document metadata: {e}")
        finally:
            conn.close()
    return None

def update_document_metadata(file_path: str, file_hash: str, version: str):
    """Saves or updates document checksum information."""
    if is_sqlite():
        conn = get_connection()
        try:
            with conn:
                conn.execute(
                    "INSERT OR REPLACE INTO document_metadata (file_path, file_hash, version) VALUES (?, ?, ?);",
                    (file_path, file_hash, version)
                )
        except Exception as e:
            logger.error(f"Error writing document metadata: {e}")
        finally:
            conn.close()
    else:
        conn = get_connection()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO document_metadata (file_path, file_hash, version)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (file_path) DO UPDATE 
                    SET file_hash = EXCLUDED.file_hash, version = EXCLUDED.version, updated_at = CURRENT_TIMESTAMP;
                """, (file_path, file_hash, version))
                conn.commit()
        except Exception as e:
            conn.rollback()
            logger.error(f"Error updating document metadata: {e}")
        finally:
            conn.close()

def delete_document_chunks(file_path: str):
    """Deletes all chunks belonging to a source file."""
    if is_sqlite():
        conn = get_connection()
        try:
            with conn:
                conn.execute("DELETE FROM knowledge_chunks WHERE source_path = ?;", (file_path,))
        except Exception as e:
            logger.error(f"Error clearing document chunks: {e}")
        finally:
            conn.close()
    else:
        conn = get_connection()
        try:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM knowledge_chunks WHERE source_path = %s;", (file_path,))
                conn.commit()
        except Exception as e:
            conn.rollback()
            logger.error(f"Error clearing document chunks: {e}")
        finally:
            conn.close()

def store_chunks(chunks: List[Dict[str, Any]]):
    """
    Stores text chunks, metadata, collection partitions, and embeddings in batch.
    """
    if is_sqlite():
        conn = get_connection()
        try:
            with conn:
                data = [
                    (
                        c['content'], 
                        json.dumps(c['embedding']), 
                        json.dumps(c['metadata']),
                        c['metadata'].get('category', 'general'),
                        c['metadata'].get('source_path', '')
                    )
                    for c in chunks
                ]
                conn.executemany(
                    "INSERT INTO knowledge_chunks (content, embedding, metadata, collection, source_path) VALUES (?, ?, ?, ?, ?);",
                    data
                )
                logger.info(f"Successfully stored {len(chunks)} chunks in SQLite database.")
        except Exception as e:
            logger.error(f"Failed to store chunks in SQLite: {e}")
            raise e
        finally:
            conn.close()
        return

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            query = """
                INSERT INTO knowledge_chunks (content, embedding, metadata, collection, source_path)
                VALUES (%s, %s, %s, %s, %s);
            """
            data = [
                (
                    c['content'], 
                    c['embedding'], 
                    PGJson(c['metadata']),
                    c['metadata'].get('category', 'general'),
                    c['metadata'].get('source_path', '')
                )
                for c in chunks
            ]
            cur.executemany(query, data)
            conn.commit()
            logger.info(f"Successfully stored {len(chunks)} chunks in vector database.")
    except Exception as e:
        conn.rollback()
        logger.error(f"Failed to store chunks: {str(e)}")
        raise e
    finally:
        conn.close()

def similarity_search(
    query_embedding: List[float], 
    limit: int = 5, 
    category_filter: Optional[str] = None,
    exclude_category: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Deprecated direct vector search wrapper. Calls hybrid_search under the hood.
    """
    return hybrid_search("", query_embedding, limit, category_filter)

def hybrid_search(
    query_text: str,
    query_embedding: List[float],
    limit: int = 5,
    collection_filter: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Performs Hybrid Search (Dense similarity + Sparse keyword matching)
    and reranks results using Reciprocal Rank Fusion (RRF).
    """
    dense_results = []
    sparse_results = []
    
    # ── 1. Dense Semantic Vector Search ──
    if is_sqlite():
        conn = get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT id, content, embedding, metadata, collection, source_path FROM knowledge_chunks;")
            rows = cursor.fetchall()
            
            scored = []
            for row in rows:
                r_id, content, emb_str, meta_str, coll, src = row
                if collection_filter and coll != collection_filter:
                    continue
                try:
                    emb = json.loads(emb_str)
                    meta = json.loads(meta_str)
                except Exception:
                    continue
                sim = cosine_similarity(query_embedding, emb)
                scored.append({
                    "id": r_id,
                    "content": content,
                    "metadata": meta,
                    "collection": coll,
                    "source_path": src,
                    "score": sim
                })
            scored.sort(key=lambda x: x["score"], reverse=True)
            dense_results = scored[:30]
        except Exception as e:
            logger.error(f"Error in SQLite dense search: {e}")
        finally:
            conn.close()
    else:
        conn = get_connection()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                if collection_filter:
                    query = """
                        SELECT id, content, metadata, collection, source_path, (1.0 - (embedding <=> %s)) AS similarity
                        FROM knowledge_chunks
                        WHERE collection = %s
                        ORDER BY similarity DESC
                        LIMIT 30;
                    """
                    cur.execute(query, (query_embedding, collection_filter))
                else:
                    query = """
                        SELECT id, content, metadata, collection, source_path, (1.0 - (embedding <=> %s)) AS similarity
                        FROM knowledge_chunks
                        ORDER BY similarity DESC
                        LIMIT 30;
                    """
                    cur.execute(query, (query_embedding,))
                rows = cur.fetchall()
                for row in rows:
                    dense_results.append({
                        "id": row["id"],
                        "content": row["content"],
                        "metadata": row["metadata"],
                        "collection": row["collection"],
                        "source_path": row["source_path"],
                        "score": float(row["similarity"])
                    })
        except Exception as e:
            logger.error(f"Error in PostgreSQL dense search: {e}")
        finally:
            conn.close()

    # ── 2. Sparse Keyword Matches (only if query text provided) ──
    if query_text and query_text.strip():
        keywords = [w.lower().strip() for w in query_text.split() if len(w.strip()) > 2]
        if not keywords:
            keywords = [query_text.lower().strip()]
            
        if is_sqlite():
            conn = get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT id, content, metadata, collection, source_path FROM knowledge_chunks;")
                rows = cursor.fetchall()
                
                scored = []
                for row in rows:
                    r_id, content, meta_str, coll, src = row
                    if collection_filter and coll != collection_filter:
                        continue
                    content_lower = content.lower()
                    matches = sum(1 for kw in keywords if kw in content_lower)
                    if matches > 0:
                        try:
                            meta = json.loads(meta_str)
                        except Exception:
                            meta = {}
                        scored.append({
                            "id": r_id,
                            "content": content,
                            "metadata": meta,
                            "collection": coll,
                            "source_path": src,
                            "matches": matches
                        })
                scored.sort(key=lambda x: x["matches"], reverse=True)
                sparse_results = scored[:30]
            except Exception as e:
                logger.error(f"Error in SQLite sparse search: {e}")
            finally:
                conn.close()
        else:
            conn = get_connection()
            try:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    ts_query = " | ".join(keywords)
                    if collection_filter:
                        query = """
                            SELECT id, content, metadata, collection, source_path, ts_rank(to_tsvector('english', content), to_tsquery('english', %s)) as rank
                            FROM knowledge_chunks
                            WHERE collection = %s AND to_tsvector('english', content) @@ to_tsquery('english', %s)
                            ORDER BY rank DESC
                            LIMIT 30;
                        """
                        cur.execute(query, (ts_query, collection_filter, ts_query))
                    else:
                        query = """
                            SELECT id, content, metadata, collection, source_path, ts_rank(to_tsvector('english', content), to_tsquery('english', %s)) as rank
                            FROM knowledge_chunks
                            WHERE to_tsvector('english', content) @@ to_tsquery('english', %s)
                            ORDER BY rank DESC
                            LIMIT 30;
                        """
                        cur.execute(query, (ts_query, ts_query))
                    rows = cur.fetchall()
                    for row in rows:
                        sparse_results.append({
                            "id": row["id"],
                            "content": row["content"],
                            "metadata": row["metadata"],
                            "collection": row["collection"],
                            "source_path": row["source_path"],
                            "score": float(row["rank"])
                        })
            except Exception as e:
                logger.warning(f"PostgreSQL FTS failed: {e}. Falling back to LIKE.")
            finally:
                conn.close()

    # ── 3. Reciprocal Rank Fusion (RRF) Reranking ──
    rrf_scores = {}
    rrf_docs = {}
    
    def add_ranks(results_list):
        for rank, doc in enumerate(results_list):
            doc_id = doc["id"]
            if doc_id not in rrf_docs:
                rrf_docs[doc_id] = doc
            if doc_id not in rrf_scores:
                rrf_scores[doc_id] = 0.0
            rrf_scores[doc_id] += 1.0 / (60.0 + (rank + 1))
            
    add_ranks(dense_results)
    add_ranks(sparse_results)
    
    sorted_doc_ids = sorted(rrf_scores.keys(), key=lambda x: rrf_scores[x], reverse=True)
    
    final_results = []
    for doc_id in sorted_doc_ids[:limit]:
        doc = rrf_docs[doc_id]
        dense_match = next((d for d in dense_results if d["id"] == doc_id), None)
        confidence = float(dense_match["score"]) if dense_match else 0.5
        
        final_results.append({
            "id": doc["id"],
            "content": doc["content"],
            "metadata": doc["metadata"],
            "collection": doc["collection"],
            "source_path": doc["source_path"],
            "confidence": confidence,
            "rrf_score": rrf_scores[doc_id]
        })
        
    return final_results
