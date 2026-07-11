"""
CrowdStrike Falcon Sensor Health Retrieval Module
==================================================
Aggregates real sensor coverage, health, and deployment data from
CrowdStrike Falcon using the Hosts and SensorUpdatePolicies service classes.

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

logger = logging.getLogger("crowdstrike_sensor")


@with_retry(max_retries=3, base_delay=1.0)
def get_sensor_coverage() -> Dict[str, Any]:
    """
    Returns a complete sensor coverage summary for the tenant.
    Includes total managed hosts, online/offline breakdown, and version stats.

    Returns:
        Dict with coverage metrics

    Raises:
        FalconAPIError: If the API call fails
    """
    falcon = get_falcon_client("Hosts")

    # Count total managed hosts
    total_response = falcon.query_devices_by_filter(filter="", limit=1)
    check_api_response(total_response, "Hosts")
    total_hosts = (
        total_response["body"]
        .get("meta", {})
        .get("pagination", {})
        .get("total", 0)
    )

    # Count online (seen in last 24h)
    since_24h = (datetime.now(timezone.utc) - timedelta(hours=24)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    online_response = falcon.query_devices_by_filter(
        filter=f"last_seen:>='{since_24h}'",
        limit=1,
    )
    check_api_response(online_response, "Hosts")
    online_count = (
        online_response["body"]
        .get("meta", {})
        .get("pagination", {})
        .get("total", 0)
    )

    # Count offline (not seen in last 7 days)
    since_7d = (datetime.now(timezone.utc) - timedelta(days=7)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    offline_response = falcon.query_devices_by_filter(
        filter=f"last_seen:<='{since_7d}'",
        limit=1,
    )
    check_api_response(offline_response, "Hosts")
    offline_count = (
        offline_response["body"]
        .get("meta", {})
        .get("pagination", {})
        .get("total", 0)
    )

    # Count RFM (Reduced Functionality Mode)
    rfm_response = falcon.query_devices_by_filter(
        filter="reduced_functionality_mode:'yes'",
        limit=1,
    )
    check_api_response(rfm_response, "Hosts")
    rfm_count = (
        rfm_response["body"]
        .get("meta", {})
        .get("pagination", {})
        .get("total", 0)
    )

    coverage_pct = round((online_count / total_hosts * 100), 2) if total_hosts > 0 else 0.0

    return {
        "total_managed_hosts": total_hosts,
        "online_last_24h": online_count,
        "offline_7d": offline_count,
        "reduced_functionality_mode": rfm_count,
        "coverage_percentage": coverage_pct,
        "as_of": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


@with_retry(max_retries=3, base_delay=1.0)
def get_offline_sensors(
    days: int = 7,
    max_results: int = 1000,
) -> List[Dict[str, Any]]:
    """
    Retrieves sensors that have not checked in within the specified days.

    Args:
        days: Days since last check-in threshold
        max_results: Maximum results to return

    Returns:
        List of offline host device dicts
    """
    from app.tools.crowdstrike.hosts import get_offline_hosts
    return get_offline_hosts(days=days, max_results=max_results)


@with_retry(max_retries=3, base_delay=1.0)
def get_version_distribution() -> Dict[str, Any]:
    """
    Returns agent version distribution across all managed hosts.

    Returns:
        Dict with version distribution data
    """
    from app.tools.crowdstrike.hosts import get_sensor_version_distribution
    distribution = get_sensor_version_distribution()

    # Find the latest version (highest version number)
    versions = list(distribution.keys())
    if versions:
        try:
            latest_version = sorted(
                versions,
                key=lambda v: [int(x) for x in v.split(".") if x.isdigit()],
                reverse=True,
            )[0]
        except Exception:
            latest_version = versions[0]

        up_to_date = distribution.get(latest_version, 0)
        outdated = sum(v for k, v in distribution.items() if k != latest_version)
    else:
        latest_version = "Unknown"
        up_to_date = 0
        outdated = 0

    return {
        "latest_version": latest_version,
        "up_to_date_count": up_to_date,
        "outdated_count": outdated,
        "version_breakdown": distribution,
    }


@with_retry(max_retries=3, base_delay=1.0)
def get_rfm_hosts(max_results: int = 1000) -> List[Dict[str, Any]]:
    """
    Retrieves hosts in Reduced Functionality Mode (RFM).

    Args:
        max_results: Maximum results to return

    Returns:
        List of host device dicts in RFM
    """
    from app.tools.crowdstrike.hosts import list_all_hosts
    return list_all_hosts(status="reduced_functionality_mode", max_results=max_results)


@with_retry(max_retries=3, base_delay=1.0)
def get_sensor_update_policies() -> List[Dict[str, Any]]:
    """
    Retrieves all sensor update policies with version settings.

    Returns:
        List of sensor update policy dicts
    """
    from app.tools.crowdstrike.policies import list_sensor_update_policies
    return list_sensor_update_policies()


def get_full_sensor_health_report() -> Dict[str, Any]:
    """
    Assembles a complete sensor health report combining coverage,
    version distribution, offline sensors, and RFM hosts.

    Returns:
        Comprehensive sensor health dict
    """
    report: Dict[str, Any] = {}

    try:
        report["coverage"] = get_sensor_coverage()
    except FalconAPIError as e:
        report["coverage"] = {"error": str(e)}

    try:
        report["version_distribution"] = get_version_distribution()
    except FalconAPIError as e:
        report["version_distribution"] = {"error": str(e)}

    try:
        report["update_policies"] = get_sensor_update_policies()
    except FalconAPIError as e:
        report["update_policies"] = {"error": str(e)}

    return report
