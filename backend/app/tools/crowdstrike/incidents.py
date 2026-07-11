"""
CrowdStrike Falcon Incidents Retrieval Module
==============================================
Retrieves real incident data from CrowdStrike Falcon using the
Incidents service class.

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

logger = logging.getLogger("crowdstrike_incidents")

BATCH_SIZE = 100


def _paginate_incidents(
    falcon,
    fql: str,
    max_results: int = 1000,
) -> List[str]:
    """
    Paginates through incident query results to retrieve all matching IDs.
    """
    all_ids: List[str] = []
    offset = 0
    page_size = min(1000, max_results)

    while True:
        response = falcon.query_incidents(
            filter=fql,
            sort="created_timestamp.desc",
            limit=page_size,
            offset=offset,
        )
        check_api_response(response, "Incidents")
        body = response["body"]
        resources = body.get("resources") or []
        all_ids.extend(resources)
        total = body.get("meta", {}).get("pagination", {}).get("total", 0)
        offset += len(resources)
        if not resources or offset >= total or len(all_ids) >= max_results:
            break

    return all_ids[:max_results]


def _fetch_incident_details(falcon, incident_ids: List[str]) -> List[Dict[str, Any]]:
    """
    Retrieves incident details in batches.
    """
    all_details: List[Dict[str, Any]] = []
    for i in range(0, len(incident_ids), BATCH_SIZE):
        batch = incident_ids[i : i + BATCH_SIZE]
        response = falcon.get_incidents(ids=batch)
        check_api_response(response, "Incidents")
        all_details.extend(response["body"].get("resources") or [])
    return all_details


@with_retry(max_retries=3, base_delay=1.0)
def query_incidents(
    hours: int = 24,
    state: Optional[str] = None,
    min_score: Optional[float] = None,
    max_results: int = 1000,
) -> List[Dict[str, Any]]:
    """
    Queries CrowdStrike Incidents API for incidents within the last N hours.

    Args:
        hours: Lookback window in hours
        state: Optional status filter e.g. "New", "In Progress", "Closed"
        min_score: Minimum fine_score threshold (0-100)
        max_results: Maximum incidents to return

    Returns:
        List of incident detail dicts from the Falcon API

    Raises:
        FalconAPIError: If the API call fails
    """
    falcon = get_falcon_client("Incidents")
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    fql_parts = [f"created_timestamp:>='{since.strftime('%Y-%m-%dT%H:%M:%SZ')}'"]

    if state:
        fql_parts.append(f"status:'{state}'")
    if min_score is not None:
        fql_parts.append(f"fine_score:>={int(min_score)}")

    fql = " + ".join(fql_parts)
    logger.info(f"Querying Falcon Incidents with FQL: {fql!r}")

    incident_ids = _paginate_incidents(falcon, fql, max_results=max_results)
    if not incident_ids:
        logger.info("No incidents found matching the query.")
        return []

    logger.info(f"Retrieving details for {len(incident_ids)} incidents...")
    return _fetch_incident_details(falcon, incident_ids)


@with_retry(max_retries=3, base_delay=1.0)
def get_incident_details(incident_id: str) -> Dict[str, Any]:
    """
    Retrieves full details for a single incident by ID.

    Args:
        incident_id: Falcon incident ID (e.g., "inc:abc123:def456")

    Returns:
        Incident detail dictionary

    Raises:
        FalconAPIError: If the incident is not found or the API call fails
        ValueError: If incident_id is empty
    """
    if not incident_id or not incident_id.strip():
        raise ValueError("incident_id must be a non-empty string")

    falcon = get_falcon_client("Incidents")
    response = falcon.get_incidents(ids=[incident_id.strip()])
    check_api_response(response, "Incidents")
    resources = response["body"].get("resources") or []
    if not resources:
        raise FalconAPIError(
            service="Incidents",
            status_code=404,
            errors=[f"Incident '{incident_id}' not found."],
        )
    return resources[0]


@with_retry(max_retries=3, base_delay=1.0)
def get_incident_behaviors(incident_id: str) -> List[Dict[str, Any]]:
    """
    Retrieves the behaviors (detection events) associated with a specific incident.

    Args:
        incident_id: Falcon incident ID

    Returns:
        List of behavior detail dicts

    Raises:
        FalconAPIError: If the API call fails
    """
    if not incident_id or not incident_id.strip():
        raise ValueError("incident_id must be a non-empty string")

    falcon = get_falcon_client("Incidents")

    # Query behavior IDs for this incident
    response = falcon.query_behaviors(filter=f"incident_id:'{incident_id.strip()}'")
    check_api_response(response, "Incidents")
    behavior_ids = response["body"].get("resources") or []

    if not behavior_ids:
        logger.info(f"No behaviors found for incident {incident_id!r}")
        return []

    # Retrieve behavior details
    details_response = falcon.get_behaviors(ids=behavior_ids)
    check_api_response(details_response, "Incidents")
    return details_response["body"].get("resources") or []


@with_retry(max_retries=3, base_delay=1.0)
def get_incident_count_by_period(hours: int = 24) -> Dict[str, Any]:
    """
    Returns incident counts and score statistics for the given time window.
    Used for executive reporting metrics.

    Args:
        hours: Lookback window in hours

    Returns:
        Dict with total count, avg_score, and status breakdown
    """
    incidents = query_incidents(hours=hours, max_results=1000)
    status_counts: Dict[str, int] = {}
    scores: List[float] = []

    for inc in incidents:
        status = inc.get("status", "Unknown")
        status_counts[status] = status_counts.get(status, 0) + 1
        score = inc.get("fine_score")
        if score is not None:
            scores.append(float(score))

    return {
        "total": len(incidents),
        "status_breakdown": status_counts,
        "avg_score": round(sum(scores) / len(scores), 2) if scores else 0,
        "max_score": max(scores) if scores else 0,
        "incidents": incidents,
    }


@with_retry(max_retries=3, base_delay=1.0)
def query_incidents_by_host(device_id: str, hours: int = 720) -> List[Dict[str, Any]]:
    """
    Retrieves incidents that involved a specific host device.

    Args:
        device_id: CrowdStrike device ID
        hours: Lookback window in hours (default 30 days)

    Returns:
        List of incident dicts
    """
    falcon = get_falcon_client("Incidents")
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    fql = (
        f"hosts.device_id:'{device_id}' + "
        f"created_timestamp:>='{since.strftime('%Y-%m-%dT%H:%M:%SZ')}'"
    )
    logger.info(f"Querying incidents for device_id={device_id!r}")

    incident_ids = _paginate_incidents(falcon, fql, max_results=1000)
    if not incident_ids:
        return []

    return _fetch_incident_details(falcon, incident_ids)
