import os
import zipfile
import xml.etree.ElementTree as ET
import logging
from typing import List, Dict, Any
from app.database import store_chunks
# We will import embeddings inside the function to avoid circular dependency
from app.rag.embeddings import get_embeddings

logger = logging.getLogger("ingest")

def parse_docx(file_path: str) -> str:
    """Reads paragraph text from a .docx file."""
    try:
        with zipfile.ZipFile(file_path) as z:
            xml_content = z.read('word/document.xml')
            root = ET.fromstring(xml_content)
            paragraphs = []
            for p in root.iter('{http://schemas.openxmlformats.org/wordprocessingml/2006/main}p'):
                texts = [node.text for node in p.iter('{http://schemas.openxmlformats.org/wordprocessingml/2006/main}t') if node.text]
                if texts:
                    paragraphs.append(''.join(texts))
            return '\n'.join(paragraphs)
    except Exception as e:
        logger.error(f"Error parsing word document {file_path}: {e}")
        return ""

def parse_text_file(file_path: str) -> str:
    """Reads text files (md, txt, rst)."""
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception as e:
        logger.error(f"Error reading file {file_path}: {e}")
        return ""

def parse_xlsx(file_path: str) -> str:
    """Reads all sheets from an Excel file using pandas and openpyxl, representing rows as text."""
    try:
        import pandas as pd
        sheets = pd.read_excel(file_path, sheet_name=None, engine='openpyxl')
        output = []
        for sheet_name, df in sheets.items():
            output.append(f"Sheet: {sheet_name}")
            df = df.dropna(how='all')
            for _, row in df.iterrows():
                row_str = " | ".join(f"{col}: {val}" for col, val in row.items() if pd.notna(val))
                if row_str.strip():
                    output.append(row_str)
        return "\n".join(output)
    except Exception as e:
        logger.error(f"Error parsing Excel file {file_path}: {e}")
        return ""

def split_text(text: str, chunk_size: int = 1000, chunk_overlap: int = 200) -> List[str]:
    """
    Semantic paragraph character splitter. Splits text by logical paragraph double newlines,
    preventing mid-sentence breaks and grouping headers with their associated bodies.
    """
    if not text:
        return []
    
    try:
        from langchain.text_splitter import RecursiveCharacterTextSplitter
        splitter = RecursiveCharacterTextSplitter(chunk_size=chunk_size, chunk_overlap=chunk_overlap, separators=["\n\n", "\n", " ", ""])
        return splitter.split_text(text)
    except (ImportError, TypeError, Exception):
        pass

    # Custom semantic splitter fallback
    paragraphs = text.split("\n\n")
    chunks = []
    current_chunk = []
    current_length = 0
    
    for p in paragraphs:
        p_len = len(p)
        if current_length + p_len > chunk_size and current_chunk:
            chunks.append("\n\n".join(current_chunk))
            # Keep overlap (last paragraph in chunk if reasonably small)
            overlap_p = current_chunk[-1] if len(current_chunk[-1]) < chunk_overlap else ""
            if overlap_p:
                current_chunk = [overlap_p, p]
                current_length = len(overlap_p) + p_len + 2
            else:
                current_chunk = [p]
                current_length = p_len
        else:
            current_chunk.append(p)
            current_length += p_len + 2
            
    if current_chunk:
        chunks.append("\n\n".join(current_chunk))
        
    return chunks

def ingest_directory(data_dir: str):
    """
    Recursively scans the data_dir, extracts contents, chunks them,
    generates embeddings, and stores them in the database incrementally.
    """
    import hashlib
    from app.database import (
        get_document_metadata,
        update_document_metadata,
        delete_document_chunks
    )

    if not os.path.exists(data_dir):
        logger.warning(f"Knowledge directory {data_dir} does not exist. Scaffolding folders...")
        os.makedirs(data_dir, exist_ok=True)
        for folder in ['falcon_docs', 'falconpy_docs', 'runbooks', 'sops', 'mitre_attack', 'tech_alerts']:
            os.makedirs(os.path.join(data_dir, folder), exist_ok=True)
        return

    logger.info(f"Scanning knowledge documents in {data_dir}...")
    
    modified_files = []
    
    for root, _, files in os.walk(data_dir):
        category = os.path.basename(root) if root != data_dir else "general"
        
        for file in files:
            file_path = os.path.join(root, file)
            ext = os.path.splitext(file)[1].lower()
            
            content = ""
            if ext in ['.md', '.txt', '.rst', '.html', '.json']:
                content = parse_text_file(file_path)
            elif ext == '.docx':
                content = parse_docx(file_path)
            elif ext == '.xlsx':
                content = parse_xlsx(file_path)
                
            if not content.strip():
                continue
                
            # Calculate SHA256 checksum of content
            file_hash = hashlib.sha256(content.encode("utf-8", errors="ignore")).hexdigest()
            
            # Check db metadata cache
            meta = get_document_metadata(file_path)
            if meta and meta["file_hash"] == file_hash:
                # File has not changed, skip!
                continue
                
            logger.info(f"File modified or new: {file} in category: {category}. Scheduling index update...")
            modified_files.append({
                "file_path": file_path,
                "file_name": file,
                "category": category,
                "content": content,
                "hash": file_hash
            })

    if not modified_files:
        logger.info("All documents are up-to-date. Incremental scan completed (0 files updated).")
        return

    # Delete old chunks for modified/new files before storing updated chunks
    for f in modified_files:
        delete_document_chunks(f["file_path"])

    # Build all chunks to embed
    all_chunks = []
    file_to_chunks_map = {}
    
    for f in modified_files:
        text_chunks = split_text(f["content"])
        file_to_chunks_map[f["file_path"]] = len(text_chunks)
        
        for i, chunk in enumerate(text_chunks):
            metadata = {
                "source": f["file_name"],
                "category": f["category"],
                "chunk_id": i,
                "source_path": f["file_path"],
                "version": "1.0"
            }
            all_chunks.append({
                "content": chunk,
                "metadata": metadata,
                "file_path": f["file_path"]
            })

    # Calculate embeddings and save in batch
    logger.info(f"Generating embeddings for {len(all_chunks)} new/modified chunks...")
    
    stored_count = 0
    batch_size = 100
    failed_files = set()

    for idx in range(0, len(all_chunks), batch_size):
        batch = all_chunks[idx : idx + batch_size]
        batch_contents = [c['content'] for c in batch]
        
        try:
            embeddings = get_embeddings(batch_contents)
            
            db_batch = []
            for i, chunk in enumerate(batch):
                db_batch.append({
                    "content": chunk["content"],
                    "metadata": chunk["metadata"],
                    "embedding": embeddings[i]
                })
                
            store_chunks(db_batch)
            stored_count += len(db_batch)
        except Exception as e:
            logger.error(f"Error processing batch {idx//batch_size + 1}: {e}")
            for c in batch:
                failed_files.add(c["file_path"])

    # Update metadata hashes only for successfully ingested files
    for f in modified_files:
        if f["file_path"] not in failed_files:
            update_document_metadata(f["file_path"], f["hash"], version="1.0")
            
    logger.info(f"Ingestion completed. Stored {stored_count} chunks across {len(modified_files) - len(failed_files)} files.")

if __name__ == "__main__":
    import sys
    sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
    
    logging.basicConfig(level=logging.INFO)
    from app.database import init_db
    
    init_db()
    
    data_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "data")
    ingest_directory(data_path)
