"""
CrowdStrike Falcon Discover Retrieval Module
=============================================
Retrieves real asset discovery data from CrowdStrike Falcon Discover
including installed applications, user accounts, and login events.

All functions are strictly read-only and return live API data.
No mock or fallback data is generated.
"""
import logging
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional
from app.tools.crowdstrike.client_factory import (
    get_falcon_client,
    check_api_response,
    with_retry,
    FalconAPIError,
)

logger = logging.getLogger("crowdstrike_discover")

BATCH_SIZE = 100


@with_retry(max_retries=3, base_delay=1.0)
def query_applications(
    name_filter: Optional[str] = None,
    vendor: Optional[str] = None,
    hostname: Optional[str] = None,
    max_results: int = 1000,
) -> List[Dict[str, Any]]:
    """
    Retrieves installed application inventory from Falcon Discover.

    Args:
        name_filter: Optional application name filter
        vendor: Optional vendor/publisher name filter
        hostname: Optional hostname filter
        max_results: Maximum applications to return

    Returns:
        List of application detail dicts

    Raises:
        FalconAPIError: If the API call fails
    """
    falcon = get_falcon_client("Discover")
    fql_parts: List[str] = []

    if name_filter:
        fql_parts.append(f"name:*'{name_filter}'*")
    if vendor:
        fql_parts.append(f"vendor:*'{vendor}'*")
    if hostname:
        fql_parts.append(f"host.hostname:'{hostname.upper()}'")

    fql = " + ".join(fql_parts)
    _fql_display = repr(fql) if fql else '(all)'
    logger.info(f"Querying Discover applications with FQL: {_fql_display}")

    all_ids: List[str] = []
    offset = 0
    page_size = min(500, max_results)

    while True:
        response = falcon.query_applications(
            filter=fql,
            sort="name.asc",
            limit=page_size,
            offset=offset,
        )
        check_api_response(response, "Discover")
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
        response = falcon.get_applications(ids=batch)
        check_api_response(response, "Discover")
        all_details.extend(response["body"].get("resources") or [])

    return all_details[:max_results]


@with_retry(max_retries=3, base_delay=1.0)
def query_accounts(
    username_filter: Optional[str] = None,
    account_type: Optional[str] = None,
    max_results: int = 1000,
) -> List[Dict[str, Any]]:
    """
    Retrieves discovered user accounts from Falcon Discover.

    Args:
        username_filter: Optional username filter
        account_type: Optional type filter e.g. "domain", "local"
        max_results: Maximum accounts to return

    Returns:
        List of account detail dicts

    Raises:
        FalconAPIError: If the API call fails
    """
    falcon = get_falcon_client("Discover")
    fql_parts: List[str] = []

    if username_filter:
        fql_parts.append(f"username:*'{username_filter}'*")
    if account_type:
        fql_parts.append(f"account_type:'{account_type}'")

    fql = " + ".join(fql_parts)
    _fql_display = repr(fql) if fql else '(all)'
    logger.info(f"Querying Discover accounts with FQL: {_fql_display}")

    all_ids: List[str] = []
    offset = 0
    page_size = min(1000, max_results)

    while True:
        response = falcon.query_accounts(
            filter=fql,
            sort="username.asc",
            limit=page_size,
            offset=offset,
        )
        check_api_response(response, "Discover")
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
        response = falcon.get_accounts(ids=batch)
        check_api_response(response, "Discover")
        all_details.extend(response["body"].get("resources") or [])

    return all_details[:max_results]


@with_retry(max_retries=3, base_delay=1.0)
def query_logins(
    hours: int = 24,
    username: Optional[str] = None,
    hostname: Optional[str] = None,
    login_type: Optional[str] = None,
    failed_only: bool = False,
    max_results: int = 1000,
) -> List[Dict[str, Any]]:
    """
    Retrieves login events from Falcon Discover.

    Args:
        hours: Lookback window in hours
        username: Optional username filter
        hostname: Optional hostname filter
        login_type: Optional login type filter e.g. "interactive", "network", "remote"
        failed_only: If True, only return failed login attempts
        max_results: Maximum login events to return

    Returns:
        List of login event dicts

    Raises:
        FalconAPIError: If the API call fails
    """
    falcon = get_falcon_client("Discover")
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    fql_parts = [f"login_timestamp:>='{since.strftime('%Y-%m-%dT%H:%M:%SZ')}'"]

    if username:
        fql_parts.append(f"username:*'{username}'*")
    if hostname:
        fql_parts.append(f"hostname:*'{hostname}'*")
    if login_type:
        fql_parts.append(f"login_type:'{login_type}'")
    if failed_only:
        fql_parts.append("login_status:'failed'")

    fql = " + ".join(fql_parts)
    logger.info(f"Querying Discover logins with FQL: {fql!r}")

    all_ids: List[str] = []
    offset = 0
    page_size = min(1000, max_results)

    while True:
        response = falcon.query_logins(
            filter=fql,
            sort="login_timestamp.desc",
            limit=page_size,
            offset=offset,
        )
        check_api_response(response, "Discover")
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
        response = falcon.get_logins(ids=batch)
        check_api_response(response, "Discover")
        all_details.extend(response["body"].get("resources") or [])

    return all_details[:max_results]


@with_retry(max_retries=3, base_delay=1.0)
def get_top_installed_software(max_results: int = 20) -> List[Dict[str, Any]]:
    """
    Returns the most widely installed applications across managed hosts.

    Returns:
        List of dicts with app name and install count
    """
    apps = query_applications(max_results=5000)
    name_counts: Dict[str, int] = {}
    for app in apps:
        name = app.get("name", "Unknown")
        name_counts[name] = name_counts.get(name, 0) + 1

    sorted_apps = sorted(name_counts.items(), key=lambda x: x[1], reverse=True)
    return [{"name": n, "host_count": c} for n, c in sorted_apps[:max_results]]
