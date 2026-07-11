"""
CrowdStrike Falcon Detections / Alerts Retrieval Module
========================================================
Retrieves real detection and alert data from CrowdStrike Falcon using the
Alerts V2 API (the new unified alerts service).

NOTE: The legacy Detects API (query_detects / get_detect_summaries) has been
decommissioned by CrowdStrike. This module uses ONLY the Alerts V2 API.

Reference: https://supportportal.crowdstrike.com/s/article/Tech-Alert-Planned-Decommission

All functions are strictly read-only and return live API data.
No mock or fallback data is generated.
"""
import logging
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional, Tuple
from app.tools.crowdstrike.client_factory import (
    get_falcon_client,
    check_api_response,
    with_retry,
    FalconAPIError,
)

logger = logging.getLogger("crowdstrike_detections")

# Alerts V2 page size limit
BATCH_SIZE = 100
PAGE_SIZE = 500


def _paginate_alerts_v2(
    falcon,
    fql: str,
    max_results: int = 5000,
) -> List[str]:
    """
    Paginates through Alerts V2 query results using composite key pagination.
    The Alerts V2 API uses 'after' cursor (composite key) pagination.

    Args:
        falcon: Authenticated Alerts service instance
        fql: FQL filter string
        max_results: Maximum number of IDs to collect

    Returns:
        List of alert composite IDs
    """
    all_ids: List[str] = []
    after_cursor: Optional[str] = None
    page_size = min(PAGE_SIZE, max_results)

    while True:
        kwargs: Dict[str, Any] = {
            "filter": fql,
            "sort": "created_timestamp.desc",
            "limit": page_size,
        }
        if after_cursor:
            kwargs["after"] = after_cursor

        response = falcon.query_alerts_v2(**kwargs)
        check_api_response(response, "Alerts")

        body = response["body"]
        resources = body.get("resources") or []
        all_ids.extend(resources)

        meta = body.get("meta", {})
        pagination = meta.get("pagination", {})
        after_cursor = pagination.get("after")

        if not resources or not after_cursor or len(all_ids) >= max_results:
            break

    return all_ids[:max_results]


def _fetch_alert_details_batch(
    falcon, alert_ids: List[str]
) -> List[Dict[str, Any]]:
    """
    Fetches alert details in batches using the Alerts V2 POST entity endpoint.

    Args:
        falcon: Authenticated Alerts service instance
        alert_ids: List of alert composite IDs to retrieve

    Returns:
        List of alert detail dictionaries
    """
    all_details: List[Dict[str, Any]] = []
    for i in range(0, len(alert_ids), BATCH_SIZE):
        batch = alert_ids[i : i + BATCH_SIZE]
        response = falcon.get_alerts_v2(ids=batch)
        check_api_response(response, "Alerts")
        all_details.extend(response["body"].get("resources") or [])
    return all_details


@with_retry(max_retries=2, base_delay=1.0)
def query_recent_detections(
    hours: int = 24,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    hostname: Optional[str] = None,
    max_results: int = 1000,
) -> List[Dict[str, Any]]:
    """
    Queries CrowdStrike Alerts V2 API for alerts within the last N hours.

    Args:
        hours: Lookback window in hours
        severity: Optional filter — "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"
        status: Optional filter — "new", "in_progress", "closed"
        hostname: Optional hostname filter
        max_results: Maximum alerts to return

    Returns:
        List of alert detail dicts from the Falcon Alerts V2 API

    Raises:
        FalconAPIError: If the API call fails
    """
    falcon = get_falcon_client("Alerts")
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    fql_parts = [f"created_timestamp:>='{since.strftime('%Y-%m-%dT%H:%M:%SZ')}'"]

    if severity:
        fql_parts.append(f"severity_name:'{severity.upper()}'")
    if status:
        fql_parts.append(f"status:'{status.lower()}'")
    if hostname:
        fql_parts.append(f"device.hostname:'{hostname.upper()}'")

    fql = " + ".join(fql_parts)
    logger.info(f"Querying Falcon Alerts V2 with FQL: {fql!r}")

    alert_ids = _paginate_alerts_v2(falcon, fql, max_results=max_results)

    if not alert_ids:
        logger.info("No alerts found matching the query.")
        return []

    logger.info(f"Retrieving details for {len(alert_ids)} alerts...")
    return _fetch_alert_details_batch(falcon, alert_ids)


@with_retry(max_retries=2, base_delay=1.0)
def get_detection_details(detection_id: str) -> Dict[str, Any]:
    """
    Retrieves full details for a single alert by composite ID.

    Args:
        detection_id: Falcon alert composite ID

    Returns:
        Alert detail dictionary

    Raises:
        FalconAPIError: If the alert is not found or API call fails
        ValueError: If detection_id is empty
    """
    if not detection_id or not detection_id.strip():
        raise ValueError("detection_id must be a non-empty string")

    falcon = get_falcon_client("Alerts")
    response = falcon.get_alerts_v2(ids=[detection_id.strip()])
    check_api_response(response, "Alerts")
    resources = response["body"].get("resources") or []
    if not resources:
        raise FalconAPIError(
            service="Alerts",
            status_code=404,
            errors=[f"Alert '{detection_id}' not found."],
        )
    return resources[0]


@with_retry(max_retries=2, base_delay=1.0)
def query_detections_by_host(
    device_id: str,
    hours: int = 168,
    max_results: int = 1000,
) -> List[Dict[str, Any]]:
    """
    Retrieves all alerts for a specific host device ID.

    Args:
        device_id: CrowdStrike device ID
        hours: Lookback window in hours (default 7 days)
        max_results: Maximum alerts to return

    Returns:
        List of alert dicts
    """
    falcon = get_falcon_client("Alerts")
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    fql = (
        f"device.device_id:'{device_id}' + "
        f"created_timestamp:>='{since.strftime('%Y-%m-%dT%H:%M:%SZ')}'"
    )
    logger.info(f"Querying host alerts for device_id={device_id!r}")

    alert_ids = _paginate_alerts_v2(falcon, fql, max_results=max_results)
    if not alert_ids:
        return []

    return _fetch_alert_details_batch(falcon, alert_ids)


@with_retry(max_retries=2, base_delay=1.0)
def get_detection_count_by_severity(hours: int = 24) -> Dict[str, int]:
    """
    Returns a count of alerts grouped by severity for the given time window.
    Uses Alerts V2 aggregations.

    Args:
        hours: Lookback window in hours

    Returns:
        Dict mapping severity name to count e.g. {"CRITICAL": 3, "HIGH": 12}
    """
    falcon = get_falcon_client("Alerts")
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    fql = f"created_timestamp:>='{since.strftime('%Y-%m-%dT%H:%M:%SZ')}'"

    counts: Dict[str, int] = {}
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]:
        sev_fql = f"{fql} + severity_name:'{severity}'"
        try:
            response = falcon.query_alerts_v2(
                filter=sev_fql,
                limit=1,
            )
            check_api_response(response, "Alerts")
            total = (
                response["body"]
                .get("meta", {})
                .get("pagination", {})
                .get("total", 0)
            )
            if total > 0:
                counts[severity] = total
        except FalconAPIError as e:
            logger.warning(f"Severity count for {severity} failed: {e}")
            counts[severity] = 0

    return counts


@with_retry(max_retries=2, base_delay=1.0)
def search_alerts_by_ioc(
    indicator_type: str,
    indicator_value: str,
    hours: int = 720,
    max_results: int = 1000,
) -> List[Dict[str, Any]]:
    """
    Searches alerts containing a specific IOC value.

    Args:
        indicator_type: IOC type — "sha256", "domain", "ipv4", "md5", "filename"
        indicator_value: The IOC value to search for
        hours: Lookback window in hours (default 30 days)
        max_results: Maximum alerts to return

    Returns:
        List of matching alert dicts
    """
    falcon = get_falcon_client("Alerts")
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    base_fql = f"created_timestamp:>='{since.strftime('%Y-%m-%dT%H:%M:%SZ')}'"

    # Map IOC types to alert FQL fields
    ioc_field_map = {
        "sha256": "triggering_process_graph_id.sha256",
        "md5": "triggering_process_graph_id.md5",
        "domain": "dns.resolution.request.name",
        "ipv4": "network.remote_address",
        "filename": "triggering_process_graph_id.filename",
    }

    fql_field = ioc_field_map.get(indicator_type.lower())
    if fql_field:
        fql = f"{base_fql} + {fql_field}:'{indicator_value}'"
    else:
        # Generic text search fallback — will likely return no results
        fql = base_fql
        logger.warning(f"No FQL field mapping for indicator_type={indicator_type!r}. Using base FQL.")

    logger.info(f"Searching alerts for IOC {indicator_type}={indicator_value!r}")
    alert_ids = _paginate_alerts_v2(falcon, fql, max_results=max_results)
    if not alert_ids:
        return []

    return _fetch_alert_details_batch(falcon, alert_ids)


def extract_behaviors_from_alert(alert: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Extracts behavior-like data from an Alerts V2 alert record.
    The new Alerts V2 schema differs from the legacy Detects schema —
    this function normalizes key fields for downstream compatibility.

    Args:
        alert: Alert dict from the Alerts V2 API

    Returns:
        List of normalized behavior-like dicts
    """
    behaviors: List[Dict[str, Any]] = []

    # Alerts V2 embeds tactic/technique at the top level or in composite_id
    tactic = alert.get("tactic")
    technique = alert.get("technique")
    technique_id = alert.get("technique_id")
    filename = alert.get("filename") or alert.get("triggering_process_graph_id", {}).get("filename")
    cmdline = alert.get("cmdline") or alert.get("command_line")
    sha256 = alert.get("sha256")
    user_name = alert.get("user_name")
    ts = alert.get("created_timestamp") or alert.get("timestamp")

    if tactic or technique:
        behaviors.append({
            "tactic": tactic,
            "technique": technique,
            "technique_id": technique_id,
            "filename": filename,
            "cmdline": cmdline,
            "sha256": sha256,
            "user_name": user_name,
            "timestamp": ts,
            "description": alert.get("description", ""),
            "network_accesses": alert.get("network_accesses", []),
            "dns_requests": alert.get("dns_requests", []),
        })

    return behaviors
