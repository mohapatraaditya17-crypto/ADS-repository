"""
CrowdStrike Falcon Policy Retrieval Module
===========================================
Retrieves real policy and exclusion data from CrowdStrike Falcon across
all policy families: Prevention, Sensor Update, Device Control, Firewall,
Response, IOA, and Host Groups.

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

logger = logging.getLogger("crowdstrike_policies")


@with_retry(max_retries=3, base_delay=1.0)
def list_prevention_policies(
    platform: Optional[str] = None,
    enabled_only: bool = False,
    max_results: int = 1000,
) -> List[Dict[str, Any]]:
    """
    Retrieves all prevention policies with full settings detail.

    Args:
        platform: Optional filter e.g. "Windows", "Linux", "Mac"
        enabled_only: If True, only return enabled policies
        max_results: Maximum results to return

    Returns:
        List of prevention policy dicts

    Raises:
        FalconAPIError: If the API call fails
    """
    falcon = get_falcon_client("PreventionPolicies")
    fql_parts: List[str] = []

    if platform:
        fql_parts.append(f"platform_name:'{platform}'")
    if enabled_only:
        fql_parts.append("enabled:'true'")

    fql = " + ".join(fql_parts)
    _fql_display = repr(fql) if fql else '(all)'
    logger.info(f"Querying prevention policies with FQL: {_fql_display}")

    kwargs = {
        "sort": "name.asc",
        "limit": min(1000, max_results),
    }
    if fql:
        kwargs["filter"] = fql
        
    response = falcon.query_combined_policies(**kwargs)
    check_api_response(response, "PreventionPolicies")
    return response["body"].get("resources") or []


@with_retry(max_retries=3, base_delay=1.0)
def get_policy_details(policy_id: str) -> Dict[str, Any]:
    """
    Retrieves full details for a specific prevention policy.

    Args:
        policy_id: Prevention policy ID

    Returns:
        Policy detail dict

    Raises:
        FalconAPIError: If policy not found or API call fails
    """
    if not policy_id or not policy_id.strip():
        raise ValueError("policy_id must be a non-empty string")

    falcon = get_falcon_client("PreventionPolicies")
    response = falcon.get_policies(ids=[policy_id.strip()])
    check_api_response(response, "PreventionPolicies")
    resources = response["body"].get("resources") or []
    if not resources:
        raise FalconAPIError(
            service="PreventionPolicies",
            status_code=404,
            errors=[f"Prevention policy '{policy_id}' not found."],
        )
    return resources[0]


@with_retry(max_retries=3, base_delay=1.0)
def list_sensor_update_policies(max_results: int = 1000) -> List[Dict[str, Any]]:
    """
    Retrieves all sensor update policies.

    Returns:
        List of sensor update policy dicts
    """
    falcon = get_falcon_client("SensorUpdatePolicies")
    response = falcon.query_combined_policies(
        limit=min(1000, max_results),
    )
    check_api_response(response, "SensorUpdatePolicies")
    return response["body"].get("resources") or []


@with_retry(max_retries=3, base_delay=1.0)
def list_device_control_policies(max_results: int = 1000) -> List[Dict[str, Any]]:
    """
    Retrieves all USB/device control policies.

    Returns:
        List of device control policy dicts
    """
    falcon = get_falcon_client("DeviceControlPolicies")
    response = falcon.query_combined_policies(
        limit=min(1000, max_results),
    )
    check_api_response(response, "DeviceControlPolicies")
    return response["body"].get("resources") or []


@with_retry(max_retries=3, base_delay=1.0)
def list_firewall_policies(max_results: int = 1000) -> List[Dict[str, Any]]:
    """
    Retrieves all Falcon Firewall Management policies.

    Returns:
        List of firewall policy dicts
    """
    falcon = get_falcon_client("FirewallPolicies")
    response = falcon.query_combined_policies(
        limit=min(1000, max_results),
    )
    check_api_response(response, "FirewallPolicies")
    return response["body"].get("resources") or []


@with_retry(max_retries=3, base_delay=1.0)
def list_response_policies(max_results: int = 1000) -> List[Dict[str, Any]]:
    """
    Retrieves all Real-Time Response (RTR) policies.

    Returns:
        List of response policy dicts
    """
    falcon = get_falcon_client("ResponsePolicies")
    response = falcon.query_combined_policies(
        limit=min(1000, max_results),
    )
    check_api_response(response, "ResponsePolicies")
    return response["body"].get("resources") or []


@with_retry(max_retries=3, base_delay=1.0)
def list_host_groups(
    name_filter: Optional[str] = None,
    group_type: Optional[str] = None,
    max_results: int = 500,
) -> List[Dict[str, Any]]:
    """
    Retrieves all host groups from Falcon, including the count of hosts applied.

    Args:
        name_filter: Optional partial name match
        group_type: Optional group type filter e.g. "static", "dynamic"
        max_results: Maximum results to return

    Returns:
        List of host group dicts
    """
    falcon = get_falcon_client("HostGroup")
    fql_parts: List[str] = []

    if name_filter:
        fql_parts.append(f"name:*'{name_filter}'*")
    if group_type:
        fql_parts.append(f"group_type:'{group_type}'")

    fql = " + ".join(fql_parts)
    kwargs = {
        "sort": "name.asc",
        "limit": min(500, max_results),
    }
    if fql:
        kwargs["filter"] = fql
    response = falcon.query_combined_host_groups(**kwargs)
    check_api_response(response, "HostGroup")
    
    resources = response["body"].get("resources") or []
    for g in resources:
        g_id = g.get("id")
        if g_id:
            try:
                member_res = falcon.query_group_members(id=g_id, limit=0)
                if member_res.get("status_code") == 200:
                    total = member_res.get("body", {}).get("meta", {}).get("pagination", {}).get("total", 0)
                    g["hosts_applied"] = total
                else:
                    g["hosts_applied"] = "NA"
            except Exception:
                g["hosts_applied"] = "NA"
        else:
            g["hosts_applied"] = "NA"
            
    return resources


@with_retry(max_retries=3, base_delay=1.0)
def get_ml_exclusions(max_results: int = 1000) -> List[Dict[str, Any]]:
    """
    Retrieves Machine Learning (ML) exclusions.

    Returns:
        List of ML exclusion dicts
    """
    falcon = get_falcon_client("MLExclusions")
    response = falcon.query_exclusions(limit=min(1000, max_results))
    check_api_response(response, "MLExclusions")
    ids = response["body"].get("resources") or []
    if not ids:
        return []
    details = falcon.get_exclusions(ids=ids)
    check_api_response(details, "MLExclusions")
    return details["body"].get("resources") or []


@with_retry(max_retries=3, base_delay=1.0)
def get_ioa_exclusions(max_results: int = 1000) -> List[Dict[str, Any]]:
    """
    Retrieves IOA (Indicator of Attack) exclusions.

    Returns:
        List of IOA exclusion dicts
    """
    falcon = get_falcon_client("IOAExclusions")
    response = falcon.query_exclusions(limit=min(1000, max_results))
    check_api_response(response, "IOAExclusions")
    ids = response["body"].get("resources") or []
    if not ids:
        return []
    details = falcon.get_exclusions(ids=ids)
    check_api_response(details, "IOAExclusions")
    return details["body"].get("resources") or []


@with_retry(max_retries=3, base_delay=1.0)
def get_sve_exclusions(max_results: int = 1000) -> List[Dict[str, Any]]:
    """
    Retrieves Sensor Visibility Exclusions (SVE).

    Returns:
        List of SVE exclusion dicts
    """
    falcon = get_falcon_client("SensorVisibilityExclusions")
    response = falcon.query_exclusions(limit=min(1000, max_results))
    check_api_response(response, "SensorVisibilityExclusions")
    ids = response["body"].get("resources") or []
    if not ids:
        return []
    details = falcon.get_exclusions(ids=ids)
    check_api_response(details, "SensorVisibilityExclusions")
    return details["body"].get("resources") or []


@with_retry(max_retries=3, base_delay=1.0)
def get_ioa_rule_groups(max_results: int = 1000) -> List[Dict[str, Any]]:
    """
    Retrieves IOA (custom) rule groups.

    Returns:
        List of IOA rule group dicts
    """
    falcon = get_falcon_client("CustomIOA")
    response = falcon.query_rule_groups_full(limit=min(1000, max_results))
    check_api_response(response, "CustomIOA")
    return response["body"].get("resources") or []


def get_all_policies_summary() -> Dict[str, List[Dict[str, Any]]]:
    """
    Retrieves a summary of all policy families in a single call.
    Gracefully handles individual policy family failures.

    Returns:
        Dict mapping policy type to list of policy dicts
    """
    summary: Dict[str, List[Dict[str, Any]]] = {}
    policy_fetchers = {
        "prevention": list_prevention_policies,
        "sensor_update": list_sensor_update_policies,
        "device_control": list_device_control_policies,
        "firewall": list_firewall_policies,
    }

    for key, fetcher in policy_fetchers.items():
        try:
            summary[key] = fetcher()
        except FalconAPIError as e:
            logger.warning(f"Failed to retrieve {key} policies: {e}")
            summary[key] = []

    return summary
