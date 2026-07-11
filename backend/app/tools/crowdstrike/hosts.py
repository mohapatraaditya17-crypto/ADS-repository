"""
CrowdStrike Falcon Hosts Retrieval Module
==========================================
Retrieves real host/endpoint data from CrowdStrike Falcon using the
Hosts and related service classes.

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

logger = logging.getLogger("crowdstrike_hosts")

BATCH_SIZE = 100


def _paginate_devices(
    falcon,
    fql: str,
    max_results: int = 5000,
) -> List[str]:
    """
    Paginates through device query results using offset-based pagination.
    """
    all_ids: List[str] = []
    offset = 0
    page_size = min(500, max_results)

    while True:
        response = falcon.query_devices_by_filter(
            filter=fql,
            limit=page_size,
            offset=offset,
        )
        check_api_response(response, "Hosts")
        body = response["body"]
        resources = body.get("resources") or []
        all_ids.extend(resources)
        total = body.get("meta", {}).get("pagination", {}).get("total", 0)
        offset += len(resources)
        if not resources or offset >= total or len(all_ids) >= max_results:
            break

    return all_ids[:max_results]


def _fetch_device_details(falcon, device_ids: List[str]) -> List[Dict[str, Any]]:
    """
    Retrieves device detail records in batches of BATCH_SIZE.
    """
    all_details: List[Dict[str, Any]] = []
    for i in range(0, len(device_ids), BATCH_SIZE):
        batch = device_ids[i : i + BATCH_SIZE]
        response = falcon.get_device_details(ids=batch)
        check_api_response(response, "Hosts")
        all_details.extend(response["body"].get("resources") or [])
    return all_details


@with_retry(max_retries=3, base_delay=1.0)
def search_host(hostname: str, max_results: int = 1000) -> List[Dict[str, Any]]:
    """
    Searches for host devices by hostname (case-insensitive partial match).

    Args:
        hostname: Hostname or partial hostname to search for
        max_results: Maximum results to return

    Returns:
        List of device detail dicts

    Raises:
        FalconAPIError: If the API call fails
        ValueError: If hostname is empty
    """
    if not hostname or not hostname.strip():
        raise ValueError("hostname must be a non-empty string")

    falcon = get_falcon_client("Hosts")
    # FQL wildcard search - try exact first, then partial
    fql = f"hostname:'{hostname.upper()}'"
    logger.info(f"Searching for host with FQL: {fql!r}")

    device_ids = _paginate_devices(falcon, fql, max_results=max_results)

    # If no exact match, try wildcard
    if not device_ids:
        fql = f"hostname:*'{hostname.upper()}'*"
        logger.info(f"Trying wildcard search: {fql!r}")
        device_ids = _paginate_devices(falcon, fql, max_results=max_results)

    if not device_ids:
        logger.info(f"No hosts found matching '{hostname}'")
        return []

    return _fetch_device_details(falcon, device_ids)


@with_retry(max_retries=3, base_delay=1.0)
def get_host_details(host_id: str) -> Dict[str, Any]:
    """
    Retrieves full device details for a single host by device ID.

    Args:
        host_id: CrowdStrike device ID

    Returns:
        Device detail dictionary

    Raises:
        FalconAPIError: If the host is not found or API call fails
        ValueError: If host_id is empty
    """
    if not host_id or not host_id.strip():
        raise ValueError("host_id must be a non-empty string")

    falcon = get_falcon_client("Hosts")
    response = falcon.get_device_details(ids=[host_id.strip()])
    check_api_response(response, "Hosts")
    resources = response["body"].get("resources") or []
    if not resources:
        raise FalconAPIError(
            service="Hosts",
            status_code=404,
            errors=[f"Host '{host_id}' not found."],
        )
    return resources[0]


@with_retry(max_retries=3, base_delay=1.0)
def list_all_hosts(
    platform: Optional[str] = None,
    status: Optional[str] = None,
    tag: Optional[str] = None,
    max_results: int = 1000,
) -> List[Dict[str, Any]]:
    """
    Lists all hosts with optional filtering. Used for sensor coverage metrics.

    Args:
        platform: Optional platform filter e.g. "Windows", "Linux", "Mac"
        status: Optional status filter e.g. "normal", "reduced_functionality"
        tag: Optional sensor tag filter (partial match)
        max_results: Maximum hosts to return

    Returns:
        List of device detail dicts

    Raises:
        FalconAPIError: If the API call fails
    """
    falcon = get_falcon_client("Hosts")
    fql_parts: List[str] = []

    if platform:
        fql_parts.append(f"platform_name:'{platform}'")
    if status:
        fql_parts.append(f"status:'{status}'")
    if tag:
        fql_parts.append(f"tags:*'{tag}'*")

    fql = " + ".join(fql_parts) if fql_parts else ""
    _fql_display = repr(fql) if fql else '(no filter)'
    logger.info(f"Listing all hosts with FQL: {_fql_display}")

    device_ids = _paginate_devices(falcon, fql, max_results=max_results)
    if not device_ids:
        return []

    return _fetch_device_details(falcon, device_ids)


@with_retry(max_retries=3, base_delay=1.0)
def get_offline_hosts(days: int = 7, max_results: int = 1000) -> List[Dict[str, Any]]:
    """
    Retrieves hosts that have not checked in within the specified number of days.

    Args:
        days: Number of days since last check-in threshold
        max_results: Maximum results to return

    Returns:
        List of offline device dicts
    """
    falcon = get_falcon_client("Hosts")
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    fql = f"last_seen:<='{cutoff.strftime('%Y-%m-%dT%H:%M:%SZ')}'"
    logger.info(f"Querying offline hosts (last_seen before {cutoff.date()})")

    device_ids = _paginate_devices(falcon, fql, max_results=max_results)
    if not device_ids:
        return []

    return _fetch_device_details(falcon, device_ids)


@with_retry(max_retries=3, base_delay=1.0)
def get_host_detections(host_id: str, hours: int = 168) -> List[Dict[str, Any]]:
    """
    Retrieves detections associated with a host device ID.

    Args:
        host_id: CrowdStrike device ID
        hours: Lookback window in hours (default 7 days)

    Returns:
        List of detection dicts
    """
    from app.tools.crowdstrike.detections import query_detections_by_host
    return query_detections_by_host(device_id=host_id, hours=hours)


@with_retry(max_retries=3, base_delay=1.0)
def get_host_login_history(
    host_id: str,
    hours: int = 168,
    max_results: int = 200,
) -> List[Dict[str, Any]]:
    """
    Retrieves login activity for a specific host from Falcon Discover.

    Args:
        host_id: CrowdStrike device ID
        hours: Lookback window in hours (default 7 days)
        max_results: Maximum login events to return

    Returns:
        List of login event dicts
    """
    try:
        falcon = get_falcon_client("Discover")
        since = datetime.now(timezone.utc) - timedelta(hours=hours)
        fql = (
            f"host_id:'{host_id}' + "
            f"login_timestamp:>='{since.strftime('%Y-%m-%dT%H:%M:%SZ')}'"
        )
        logger.info(f"Querying login history for host {host_id!r}")

        response = falcon.query_logins(
            filter=fql,
            sort="login_timestamp.desc",
            limit=min(200, max_results),
        )
        check_api_response(response, "Discover")
        login_ids = response["body"].get("resources") or []

        if not login_ids:
            return []

        detail_response = falcon.get_logins(ids=login_ids)
        check_api_response(detail_response, "Discover")
        return detail_response["body"].get("resources") or []

    except FalconAPIError:
        raise
    except Exception as e:
        logger.warning(f"Login history query failed for host {host_id}: {e}")
        raise FalconAPIError(
            service="Discover",
            status_code=0,
            errors=[f"Failed to retrieve login history: {e}"],
            scope_hint="Falcon Discover: Read",
        )


@with_retry(max_retries=3, base_delay=1.0)
def get_sensor_version_distribution() -> Dict[str, int]:
    """
    Returns distribution of agent_version across all managed hosts.
    Used for sensor health dashboards and reports.

    Returns:
        Dict mapping version string to host count
    """
    hosts = list_all_hosts(max_results=10000)
    distribution: Dict[str, int] = {}
    for host in hosts:
        version = host.get("agent_version", "Unknown")
        distribution[version] = distribution.get(version, 0) + 1
    return distribution


@with_retry(max_retries=3, base_delay=1.0)
def get_host_groups(max_results: int = 1000) -> List[Dict[str, Any]]:
    """
    Retrieves all host groups defined in Falcon.

    Returns:
        List of host group dicts

    Raises:
        FalconAPIError: If the API call fails
    """
    falcon = get_falcon_client("HostGroup")
    response = falcon.query_combined_host_groups(limit=min(1000, max_results))
    check_api_response(response, "HostGroup")
    return response["body"].get("resources") or []
