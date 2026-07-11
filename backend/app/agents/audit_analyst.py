import logging
import time
from typing import Generator, List, Dict, Any
from app.tools.crowdstrike.audit import list_api_clients, check_integration_health
from app.agents.llm import call_llm_stream

logger = logging.getLogger("audit_analyst")

SYSTEM_PROMPT = """
You are the "Audit Analyst" agent for the Falcon AI Copilot. Your role is to examine the OAuth2 API clients, permissions, scopes, RBAC assignments, and third-party integrations health.

CRITICAL INSTRUCTIONS:
1. Present all active API clients and scopes in a clean Markdown table showing Client Name | Client ID | Active Scopes | Status.
2. Flag "Over-provisioned Scopes" as high priority alerts. Specifically, highlight any client names containing "Jenkins", "Legacy", or "Dev" that have write scopes (e.g. RTR:Write or Hosts:Write) if they are not actively required.
3. Review ServiceNow, Splunk, and cloud account registration integration states and list their health statuses.
4. Falcon AI Copilot is strictly READ-ONLY. Suggest that developers clean up unneeded write scopes manually inside the CrowdStrike API keys dashboard.
5. STRICT ANTI-HALLUCINATION RULE: If you are unable to answer a question or if the API returns an error or no data, DO NOT make up or hallucinate any data. You MUST return a clear statement explaining the reason (e.g., "couldn't reach server", "unable to verify", "API error", "no records found").
"""

def run_audit_analyst(
    user_query: str, 
    chat_history: List[Dict[str, str]] = []
) -> Generator[Dict[str, Any], None, None]:
    """
    Audit Analyst Agent runner. Gathers API keys and integration health status and streams findings.
    """
    logger.info(f"Running Audit Analyst for query: '{user_query}'")
    
    # 1. State transition notification
    yield {
        "event": "agent_state",
        "data": {
            "agent": "Audit Analyst",
            "message": "Auditing active CrowdStrike API credentials..."
        }
    }
    
    # Query API keys
    yield {
        "event": "tool_start",
        "data": {
            "name": "list_api_clients",
            "params": {}
        }
    }
    
    start_time = time.time()
    clients = list_api_clients()
    duration = int((time.time() - start_time) * 1000)
    
    yield {
        "event": "tool_complete",
        "data": {
            "name": "list_api_clients",
            "status": "success",
            "duration_ms": duration,
            "result": {"clients_found": len(clients)}
        }
    }
    
    # Query integrations health
    yield {
        "event": "agent_state",
        "data": {
            "agent": "Audit Analyst",
            "message": "Retrieving external integration health checks..."
        }
    }
    
    yield {
        "event": "tool_start",
        "data": {
            "name": "check_integration_health",
            "params": {}
        }
    }
    
    start_time_intel = time.time()
    health = check_integration_health()
    duration_intel = int((time.time() - start_time_intel) * 1000)
    
    yield {
        "event": "tool_complete",
        "data": {
            "name": "check_integration_health",
            "status": "success",
            "duration_ms": duration_intel,
            "result": health
        }
    }
    
    yield {
        "event": "agent_state",
        "data": {
            "agent": "Audit Analyst",
            "message": "Compiling compliance audit report..."
        }
    }
    
    # Build prompt context
    prompt_context = f"API Clients Inventory:\n{clients}\n\nExternal Integration Health:\n{health}"
    
    # Call LLM stream
    try:
        user_prompt = f"User Request: {user_query}\n\nAudited Configurations context from Falcon API:\n{prompt_context}"
        token_stream = call_llm_stream(SYSTEM_PROMPT, user_prompt, chat_history)
        for token in token_stream:
            yield {
                "event": "text_chunk",
                "data": {"text": token}
            }
    except Exception as e:
        logger.error(f"Error in Audit Analyst LLM stream: {e}")
        yield {
            "event": "text_chunk",
            "data": {"text": f"\n[Error: Failed generating compliance audit. Detail: {str(e)}]\n"}
        }
        
    yield {
        "event": "complete",
        "data": {
            "agent": "Audit Analyst",
            "status": "success"
        }
    }
