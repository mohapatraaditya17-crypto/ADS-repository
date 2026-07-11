import logging
import time
from typing import Generator, List, Dict, Any
from app.agents.llm import call_llm_stream

logger = logging.getLogger("threat_hunter")

SYSTEM_PROMPT = """
You are the lead "Threat Hunter" agent for the Falcon AI Copilot. Your role is to convert natural language hunting hypotheses into optimized search queries and signatures.

CORE PILLARS:
1. STRICT ZERO-HALLUCINATION GUARDRAIL: Never guess, fabricate, or invent telemetry, Falcon REST APIs, FalconPy methods, MITRE techniques, or CrowdStrike features. If information cannot be verified from the local knowledge base or live Falcon APIs, state so explicitly.
2. HYPOTHESIS-DRIVEN HUNT LIFE CYCLE: For every hunt, you MUST structure your output strictly under these headings:
   - **Hypothesis**: The security hypothesis statement.
   - **MITRE Mapping**: Tactics and technique names/IDs.
   - **FQL Query**: Optimized Falcon Query Language.
   - **LogScale CQL Query**: CrowdStrike SIEM Query Language.
   - **Splunk SPL Query**: Enterprise indexer queries.
   - **Sigma Rule**: Complete, valid Sigma detection rule (YAML format).
   - **YARA Rule**: Complete, valid YARA signature block.
   - **Live Indicators / Correlation**: Analyze active matching patterns in the live environment context.
   - **Prioritization & Recommendations**: High/Medium/Low priority ranking with containment next steps.
   - **Executive Summary**: Non-technical impact statement.
"""

def run_threat_hunter(
    user_query: str, 
    chat_history: List[Dict[str, str]] = []
) -> Generator[Dict[str, Any], None, None]:
    """
    Threat Hunter Agent runner. Generates target search queries, Sigma rules, and YARA rules.
    """
    logger.info(f"Running Threat Hunter for: '{user_query}'")
    
    yield {
        "event": "agent_state",
        "data": {
            "agent": "Threat Hunter",
            "message": "Formulating hypothesis and checking live Falcon indicators..."
        }
    }
    
    # Live environment validation check
    from app.tools.crowdstrike.detections import query_recent_detections
    
    t0 = time.time()
    detections = []
    try:
        detections = query_recent_detections(hours=24, max_results=10)
    except Exception as e:
        logger.warning(f"Failed querying recent detections in hunt check: {e}")
        
    duration_ms = int((time.time() - t0) * 1000)
    
    yield {
        "event": "tool_complete",
        "data": {
            "name": "query_recent_detections",
            "status": "success",
            "duration_ms": duration_ms,
            "result": {"checked_alerts": len(detections) if detections else 0}
        }
    }
    
    yield {
        "event": "agent_state",
        "data": {
            "agent": "Threat Hunter",
            "message": "Generating queries, Sigma rules, and YARA signatures..."
        }
    }
    
    try:
        user_prompt = (
            f"Hunting Request / Hypothesis: {user_query}\n\n"
            f"Active Environment Detections Context (last 24h):\n{detections}\n"
        )
        token_stream = call_llm_stream(SYSTEM_PROMPT, user_prompt, chat_history)
        for token in token_stream:
            yield {
                "event": "text_chunk",
                "data": {"text": token}
            }
    except Exception as e:
        logger.error(f"Error in Threat Hunter stream: {e}")
        yield {
            "event": "text_chunk",
            "data": {"text": f"\n[Error: Failed generating queries. Detail: {str(e)}]\n"}
        }
        
    yield {
        "event": "complete",
        "data": {
            "agent": "Threat Hunter",
            "status": "success"
        }
    }
