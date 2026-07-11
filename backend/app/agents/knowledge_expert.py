import logging
from typing import Generator, List, Dict, Any
from app.rag.retriever import retrieve_relevant_chunks
from app.agents.llm import call_llm_stream

logger = logging.getLogger("knowledge_expert")

SYSTEM_PROMPT = """
You are the "Knowledge Expert" agent for the Falcon AI Copilot. Your role is to answer questions about the CrowdStrike Falcon platform, its architecture, modules, policies, rules, APIs, and procedures.

You must ground your answers strictly in the retrieved documentation context. If the context does not contain enough information to answer the question, state that clearly.

CRITICAL INSTRUCTIONS:
1. Cite your sources directly using the file name and category details from the metadata (e.g. "Source: [file_name.md](category)").
2. Provide direct links to specific policies, documents, or API files if mentioned in the context.
3. Be professional, concise, and structured.
4. Falcon AI Copilot operates strictly in READ-ONLY mode. Do not suggest running write actions unless clarifying they must be executed manually in the Falcon Console.
5. STRICT ANTI-HALLUCINATION RULE: If you are unable to answer a question or if the API returns an error or no data, DO NOT make up or hallucinate any data. You MUST return a clear statement explaining the reason (e.g., "couldn't reach server", "unable to verify", "API error", "no records found").
6. LASER-FOCUS RULE: Provide answers strictly aligned with the specific keywords and intent of the user's query. Do not provide generalized overviews, unsolicited tangential information, or verbose preambles. Keep responses concise and directly address the exact ask.
"""

def run_knowledge_expert(
    user_query: str, 
    chat_history: List[Dict[str, str]] = []
) -> Generator[Dict[str, Any], None, None]:
    """
    Main runner for the Knowledge Expert agent.
    First retrieves documents, then yields status logs, tool outputs, and LLM text tokens.
    """
    logger.info(f"Running Knowledge Expert for: '{user_query}'")
    
    # 1. State/Agent transition notification
    yield {
        "event": "agent_state",
        "data": {
            "agent": "Knowledge Expert",
            "message": "Retrieving CrowdStrike documentation..."
        }
    }
    
    # 2. Start retrieving
    yield {
        "event": "tool_start",
        "data": {
            "name": "retrieve_relevant_chunks",
            "params": {"query": user_query, "limit": 4, "exclude_category": "falconpy_docs"}
        }
    }
    
    import time
    start_time = time.time()
    
    # We retrieve from all categories or filter based on context
    chunks = retrieve_relevant_chunks(user_query, limit=4, exclude_category="falconpy_docs")
    duration_ms = int((time.time() - start_time) * 1000)
    
    # 3. Tool completion notification
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
    
    # 4. Synthesize prompt
    context_str = ""
    for idx, chunk in enumerate(chunks):
        meta = chunk['metadata']
        context_str += f"--- DOCUMENT CHUNK {idx+1} (Source: {meta['source']}, Category: {meta['category']}) ---\n"
        context_str += f"{chunk['content']}\n\n"
        
    user_prompt = f"User Question: {user_query}\n\nRetrieved Grounding Context:\n{context_str}"
    
    yield {
        "event": "agent_state",
        "data": {
            "agent": "Knowledge Expert",
            "message": "Synthesizing answer from retrieved documentation..."
        }
    }
    
    # 5. Call LLM and stream text tokens
    try:
        token_stream = call_llm_stream(SYSTEM_PROMPT, user_prompt, chat_history)
        for token in token_stream:
            yield {
                "event": "text_chunk",
                "data": {"text": token}
            }
    except Exception as e:
        logger.error(f"Error during LLM stream in Knowledge Expert: {e}")
        yield {
            "event": "text_chunk",
            "data": {"text": f"\n[Error: Failed generating response. Detail: {str(e)}]\n"}
        }
        
    yield {
        "event": "complete",
        "data": {
            "agent": "Knowledge Expert",
            "status": "success"
        }
    }
