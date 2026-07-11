import logging
import time
from typing import Generator, List, Dict, Any
from app.rag.retriever import retrieve_relevant_chunks
from app.agents.llm import call_llm_stream

logger = logging.getLogger("falcon_engineer")

SYSTEM_PROMPT = """
You are the lead "Falcon Engineer" agent for the Falcon AI Copilot. You are a production-grade FalconPy expert. 
Your role is to write clean, production-ready scripting examples for developers and operations teams.

CORE PILLARS:
1. STRICT ZERO-HALLUCINATION GUARDRAIL: Never guess, fabricate, or invent SDK classes, methods, API endpoints, parameters, or response schemas. If the retrieved documentation does not support it, state explicitly that you cannot verify the capability and refuse to guess.
2. SDK VALIDATION REQUIREMENT: Before outputting any code block, you MUST document a structured validation header verifying:
   - **Service Class**: Mapped FalconPy class.
   - **Method**: Exact method signature.
   - **Parameters**: Mapped arguments.
   - **Return Schema**: Mapped response JSON keys.
   - **OAuth Scope**: Required API permissions.
   - **Pagination**: Methods for paginating results (if applicable).
"""

def run_falcon_engineer(
    user_query: str, 
    chat_history: List[Dict[str, str]] = []
) -> Generator[Dict[str, Any], None, None]:
    """
    Falcon Engineer Agent runner. Generates target scripts.
    """
    logger.info(f"Running Falcon Engineer for: '{user_query}'")
    
    # 1. State/Agent transition notification
    yield {
        "event": "agent_state",
        "data": {
            "agent": "Falcon Engineer",
            "message": "Retrieving FalconPy engineering documentation..."
        }
    }
    
    yield {
        "event": "tool_start",
        "data": {
            "name": "retrieve_relevant_chunks",
            "params": {"query": user_query, "category_filter": "falconpy_docs"}
        }
    }
    
    import time
    start_time = time.time()
    chunks = retrieve_relevant_chunks(user_query, limit=5, category_filter="falconpy_docs")
    duration_ms = int((time.time() - start_time) * 1000)
    
    yield {
        "event": "tool_complete",
        "data": {
            "name": "retrieve_relevant_chunks",
            "status": "success",
            "duration_ms": duration_ms,
            "result": {
                "chunks_found": len(chunks),
                "sources": list(set([c['metadata']['source'] for c in chunks]))
            }
        }
    }
    
    # Format retrieved chunks into context
    context_str = ""
    for idx, chunk in enumerate(chunks):
        meta = chunk['metadata']
        context_str += f"--- DOCUMENT CHUNK {idx+1} (Source: {meta['source']}) ---\n"
        context_str += f"{chunk['content']}\n\n"
        
    user_prompt = f"User Request: {user_query}\n\nRetrieved FalconPy Documentation:\n{context_str}"
    
    yield {
        "event": "agent_state",
        "data": {
            "agent": "Falcon Engineer",
            "message": "Generating Python FalconPy script and PowerShell REST template..."
        }
    }
    
    # 2. Call LLM and stream tokens
    try:
        token_stream = call_llm_stream(SYSTEM_PROMPT, user_prompt, chat_history)
        for token in token_stream:
            yield {
                "event": "text_chunk",
                "data": {"text": token}
            }
    except Exception as e:
        logger.error(f"Error in Falcon Engineer stream: {e}")
        yield {
            "event": "text_chunk",
            "data": {"text": f"\n[Error: Failed generating scripts. Detail: {str(e)}]\n"}
        }
        
    yield {
        "event": "complete",
        "data": {
            "agent": "Falcon Engineer",
            "status": "success"
        }
    }
