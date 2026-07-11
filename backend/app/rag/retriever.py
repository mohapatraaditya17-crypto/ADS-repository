import re
import logging
from typing import List, Dict, Any, Optional
from app.rag.embeddings import get_single_embedding

logger = logging.getLogger("retriever")

def route_query(query: str) -> str:
    """
    Deterministically routes a query to the most appropriate knowledge collection.
    """
    q = query.lower()
    
    # 1. FalconPy SDK
    if any(k in q for k in ["sdk", "falconpy", "serviceclass", "uber class", "client_factory"]):
        return "falconpy_docs"
    # 2. Falcon REST API Reference
    elif any(k in q for k in ["get /", "post /", "patch /", "delete /", "api reference", "swagger", "endpoint"]):
        return "api_ref"
    # 3. MITRE ATT&CK Mapping
    elif any(k in q for k in ["mitre", "tactic", "technique", "kill chain", "attack path", "t1003", "t1021", "t1486"]):
        return "mitre_attack"
    # 4. Threat Intelligence
    elif any(k in q for k in ["actor", "campaign", "malware", "threat intel", "reputation", "indicator", "ioc"]):
        return "threat_intel"
    # 5. Threat Hunting
    elif any(k in q for k in ["sigma", "yara", "splunk", "logscale", "cql", "spl", "fql", "hunt query"]):
        return "threat_hunting"
    # 6. Investigation Playbooks
    elif any(k in q for k in ["playbook", "sop", "standard operating", "procedures", "scenario"]):
        return "playbooks"
    # 7. OS Internals (Windows / Linux)
    elif any(k in q for k in ["registry", "process tree", "handle", "lsass", "memory", "kernel", "namespace", "privilege"]):
        return "os_internals"
    # 8. Active Policies
    elif any(k in q for k in ["prevention", "firewall", "exclusion", "device control"]):
        return "policies"
    # 9. Customer Runbooks
    elif any(k in q for k in ["migration", "raci", "deployment tracker", "brd", "connectors"]):
        return "runbooks"
        
    # Default: Falcon docs
    return "falcon_docs"

def retrieve_relevant_chunks(
    query_text: str, 
    limit: int = 5, 
    category_filter: Optional[str] = None,
    exclude_category: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Calculates embedding for raw user query and retrieves hybrid chunks from targeted partition collection.
    """
    if not query_text.strip():
        return []
        
    col_filter = category_filter
    if not col_filter:
        col_filter = route_query(query_text)
        logger.info(f"Routed query {query_text!r} to collection {col_filter!r}")

    logger.info(f"Retrieving hybrid chunks for: {query_text!r} (Collection: {col_filter})")
    
    try:
        query_embedding = get_single_embedding(query_text)
        
        from app.database import hybrid_search
        matches = hybrid_search(
            query_text=query_text,
            query_embedding=query_embedding,
            limit=limit,
            collection_filter=col_filter
        )
        
        logger.info(f"Retrieved {len(matches)} hybrid chunks with confidence scoring.")
        return matches
    except Exception as e:
        logger.error(f"Failed to retrieve hybrid chunks: {e}")
        return []
