"""
CrowdStrike Falcon Threat Intelligence Retrieval Module
========================================================
Retrieves real threat intelligence data from CrowdStrike Falcon using the
Intel service class.

All functions are strictly read-only and return live API data.
No mock or fallback data is generated.
"""
import logging
from typing import List, Dict, Any, Optional
from app.tools.crowdstrike.client_factory import (
    get_falcon_client,
    check_api_response,
    with_retry,
    FalconAPIError,
)

logger = logging.getLogger("crowdstrike_intel")

BATCH_SIZE = 100
VALID_INDICATOR_TYPES = {
    "sha256", "sha1", "md5", "ip_address", "ipv4", "ipv6",
    "domain", "url", "email_address", "registry", "mutex",
    "service", "cert_sn", "ja3", "ja3s",
}


@with_retry(max_retries=3, base_delay=1.0)
def search_indicators(
    value: Optional[str] = None,
    indicator_type: Optional[str] = None,
    malicious_confidence: Optional[str] = None,
    threat_type: Optional[str] = None,
    max_results: int = 1000,
) -> List[Dict[str, Any]]:
    """
    Searches CrowdStrike Falcon Intelligence for indicators (IOCs).

    Args:
        value: The indicator value to search for (e.g., a hash, domain, IP)
        indicator_type: Type filter e.g. "sha256", "domain", "ip_address"
        malicious_confidence: "high", "medium", "low"
        threat_type: e.g. "malware", "actor", "tool"
        max_results: Maximum results to return

    Returns:
        List of indicator detail dicts

    Raises:
        FalconAPIError: If the API call fails
    """
    falcon = get_falcon_client("Intel")
    fql_parts: List[str] = []

    if value:
        fql_parts.append(f"indicator:'{value}'")
    if indicator_type and indicator_type in VALID_INDICATOR_TYPES:
        fql_parts.append(f"type:'{indicator_type}'")
    if malicious_confidence:
        fql_parts.append(f"malicious_confidence:'{malicious_confidence.lower()}'")
    if threat_type:
        fql_parts.append(f"threat_types:'{threat_type.lower()}'")

    fql = " + ".join(fql_parts)
    logger.info(f"Searching Falcon Intel indicators with FQL: {fql!r}")

    response = falcon.query_indicator_entities(
        filter=fql,
        sort="last_updated.desc",
        limit=min(1000, max_results),
    )
    check_api_response(response, "Intel")
    return response["body"].get("resources") or []


@with_retry(max_retries=3, base_delay=1.0)
def lookup_ioc(indicator_type: str, value: str) -> Dict[str, Any]:
    """
    Looks up a single IOC value against Falcon Intelligence.

    Args:
        indicator_type: The type of indicator (e.g., "sha256", "domain")
        value: The indicator value

    Returns:
        Indicator detail dict, or empty dict if not found

    Raises:
        FalconAPIError: If the API call fails
        ValueError: If value is empty
    """
    if not value or not value.strip():
        raise ValueError("IOC value must be a non-empty string")

    results = search_indicators(value=value.strip(), indicator_type=indicator_type)
    if not results:
        logger.info(f"No intelligence data found for IOC: {value!r}")
        return {"value": value, "type": indicator_type, "found": False}
    return results[0]


@with_retry(max_retries=3, base_delay=1.0)
def get_threat_actors(
    name_filter: Optional[str] = None,
    origin: Optional[str] = None,
    target_industry: Optional[str] = None,
    max_results: int = 1000,
) -> List[Dict[str, Any]]:
    """
    Retrieves threat actor profiles from Falcon Intelligence.

    Args:
        name_filter: Actor name or alias to search for
        origin: Country/region of origin filter
        target_industry: Target industry filter
        max_results: Maximum results to return

    Returns:
        List of threat actor detail dicts

    Raises:
        FalconAPIError: If the API call fails
    """
    falcon = get_falcon_client("Intel")
    fql_parts: List[str] = []

    if name_filter:
        fql_parts.append(f"name:*'{name_filter.upper()}'*")
    if origin:
        fql_parts.append(f"origins:'{origin}'")
    if target_industry:
        fql_parts.append(f"target_industries:'{target_industry}'")

    fql = " + ".join(fql_parts)
    _fql_display = repr(fql) if fql else '(all actors)'
    logger.info(f"Querying threat actors with FQL: {_fql_display}")

    kwargs = {
        "sort": "last_activity_date.desc",
        "limit": min(1000, max_results),
    }
    if fql:
        kwargs["filter"] = fql
        
    response = falcon.query_actor_entities(**kwargs)
    check_api_response(response, "Intel")
    actor_ids = response["body"].get("resources") or []

    if not actor_ids:
        return []

    # Get full actor details
    details_response = falcon.get_actor_entities(ids=actor_ids)
    check_api_response(details_response, "Intel")
    return details_response["body"].get("resources") or []


@with_retry(max_retries=3, base_delay=1.0)
def get_threat_actor(actor_name: str) -> Dict[str, Any]:
    """
    Retrieves a specific threat actor profile by name.

    Args:
        actor_name: The actor name e.g. "WIZARD SPIDER", "FANCY BEAR"

    Returns:
        Threat actor detail dict, or empty dict if not found

    Raises:
        FalconAPIError: If the API call fails
    """
    results = get_threat_actors(name_filter=actor_name, max_results=5)
    if not results:
        logger.info(f"No threat actor profile found for: {actor_name!r}")
        return {"name": actor_name, "found": False}
    return results[0]


@with_retry(max_retries=3, base_delay=1.0)
def search_intel_reports(
    keyword: Optional[str] = None,
    threat_type: Optional[str] = None,
    max_results: int = 20,
) -> List[Dict[str, Any]]:
    """
    Searches CrowdStrike Intelligence reports (e.g., CSA, CSITs).

    Args:
        keyword: Keyword/title search term
        threat_type: e.g. "ransomware", "apt", "criminal"
        max_results: Maximum reports to return

    Returns:
        List of intelligence report summary dicts

    Raises:
        FalconAPIError: If the API call fails
    """
    falcon = get_falcon_client("Intel")
    fql_parts: List[str] = []

    if keyword:
        fql_parts.append(f"name:*'{keyword}'*")
    if threat_type:
        fql_parts.append(f"threat_types:'{threat_type}'")

    fql = " + ".join(fql_parts)
    logger.info(f"Searching Intel reports with FQL: {fql!r}")

    kwargs = {
        "sort": "created_date.desc",
        "limit": min(100, max_results),
    }
    if fql:
        kwargs["filter"] = fql
        
    response = falcon.query_report_entities(**kwargs)
    check_api_response(response, "Intel")
    report_ids = response["body"].get("resources") or []

    if not report_ids:
        return []

    details_response = falcon.get_report_entities(ids=report_ids)
    check_api_response(details_response, "Intel")
    return details_response["body"].get("resources") or []


@with_retry(max_retries=3, base_delay=1.0)
def get_malware_families(max_results: int = 50) -> List[Dict[str, Any]]:
    """
    Retrieves known malware families tracked in Falcon Intelligence.

    Returns:
        List of malware family indicator groups
    """
    return search_indicators(
        threat_type="malware",
        malicious_confidence="high",
        max_results=max_results,
    )
