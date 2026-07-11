"""
CrowdStrike Falcon Custom IOC Retrieval Module
===============================================
Retrieves real custom IOC (Indicator of Compromise) data from
CrowdStrike Falcon using the IOC service class.

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

logger = logging.getLogger("crowdstrike_iocs")

BATCH_SIZE = 100
VALID_IOC_TYPES = {
    "sha256", "sha1", "md5",
    "domain", "ipv4", "ipv6",
    "url", "email", "cert",
}


@with_retry(max_retries=3, base_delay=1.0)
def list_custom_iocs(
    ioc_type: Optional[str] = None,
    action: Optional[str] = None,
    platforms: Optional[List[str]] = None,
    max_results: int = 1000,
) -> List[Dict[str, Any]]:
    """
    Retrieves the list of custom IOCs defined in the Falcon tenant.

    Args:
        ioc_type: Filter by IOC type e.g. "sha256", "domain", "ipv4"
        action: Filter by action e.g. "detect", "prevent", "no_action"
        platforms: Optional platform list e.g. ["windows", "linux"]
        max_results: Maximum IOCs to return

    Returns:
        List of custom IOC dicts

    Raises:
        FalconAPIError: If the API call fails
    """
    falcon = get_falcon_client("IOC")
    fql_parts: List[str] = []

    if ioc_type and ioc_type.lower() in VALID_IOC_TYPES:
        fql_parts.append(f"type:'{ioc_type.lower()}'")
    if action:
        fql_parts.append(f"action:'{action.lower()}'")

    fql = " + ".join(fql_parts)
    _fql_display = repr(fql) if fql else '(all)'
    logger.info(f"Querying custom IOCs with FQL: {_fql_display}")

    all_ids: List[str] = []
    offset = 0
    page_size = min(1000, max_results)

    while True:
        kwargs: Dict[str, Any] = {
            "sort": "created_on.desc",
            "limit": page_size,
            "offset": offset,
        }
        if fql:
            kwargs["filter"] = fql
        if platforms:
            kwargs["platforms"] = platforms

        response = falcon.indicator_search_v1(**kwargs)
        check_api_response(response, "IOC")
        body = response["body"]
        resources = body.get("resources") or []
        all_ids.extend(resources)
        total = body.get("meta", {}).get("pagination", {}).get("total", 0)
        offset += len(resources)
        if not resources or offset >= total or len(all_ids) >= max_results:
            break

    if not all_ids:
        return []

    all_details: List[Dict[str, Any]] = []
    for i in range(0, len(all_ids), BATCH_SIZE):
        batch = all_ids[i : i + BATCH_SIZE]
        response = falcon.indicator_get_v1(ids=batch)
        check_api_response(response, "IOC")
        all_details.extend(response["body"].get("resources") or [])

    return all_details[:max_results]


@with_retry(max_retries=3, base_delay=1.0)
def search_ioc_by_value(value: str) -> Optional[Dict[str, Any]]:
    """
    Searches for a specific custom IOC by its indicator value.

    Args:
        value: The IOC value to search for (hash, domain, IP, etc.)

    Returns:
        IOC detail dict or None if not found

    Raises:
        FalconAPIError: If the API call fails
        ValueError: If value is empty
    """
    if not value or not value.strip():
        raise ValueError("IOC value must be a non-empty string")

    falcon = get_falcon_client("IOC")
    fql = f"value:'{value.strip()}'"
    logger.info(f"Searching for custom IOC: {value!r}")

    response = falcon.indicator_search_v1(filter=fql, limit=5)
    check_api_response(response, "IOC")
    ioc_ids = response["body"].get("resources") or []

    if not ioc_ids:
        logger.info(f"No custom IOC found matching value: {value!r}")
        return None

    detail_response = falcon.indicator_get_v1(ids=[ioc_ids[0]])
    check_api_response(detail_response, "IOC")
    resources = detail_response["body"].get("resources") or []
    return resources[0] if resources else None


@with_retry(max_retries=3, base_delay=1.0)
def get_ioc_count_by_type() -> Dict[str, int]:
    """
    Returns counts of custom IOCs grouped by type.

    Returns:
        Dict mapping IOC type to count
    """
    all_iocs = list_custom_iocs(max_results=10000)
    type_counts: Dict[str, int] = {}
    for ioc in all_iocs:
        t = ioc.get("type", "unknown")
        type_counts[t] = type_counts.get(t, 0) + 1
    return type_counts


@with_retry(max_retries=3, base_delay=1.0)
def get_prevention_iocs(max_results: int = 1000) -> List[Dict[str, Any]]:
    """
    Returns only custom IOCs configured with 'prevent' action.

    Returns:
        List of blocking IOC dicts
    """
    return list_custom_iocs(action="prevent", max_results=max_results)
