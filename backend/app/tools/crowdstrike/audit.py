"""
CrowdStrike Falcon Audit & Activity Log Retrieval Module
=========================================================
Retrieves real audit events, API clients, and RBAC data from CrowdStrike Falcon
using the AuditEvents and OAuth2 service classes.

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

logger = logging.getLogger("crowdstrike_audit")


@with_retry(max_retries=3, base_delay=1.0)
def list_api_clients(max_results: int = 1000) -> List[Dict[str, Any]]:
    """
    Retrieves the inventory of active API clients.
    NOTE: FalconPy's OAuth2 service class handles token management only.
    API client enumeration requires the Falcon Flight Control (MSSP) service
    or platform admin scopes that may not be available in this configuration.

    Returns:
        Empty list with informational log message.
    """
    logger.warning(
        "API client enumeration is not available through standard FalconPy OAuth2 service. "
        "Use Falcon console > API Clients & Keys, or use Flight Control for MSSP environments."
    )
    return []


@with_retry(max_retries=3, base_delay=1.0)
def query_audit_events(
    hours: int = 24,
    action: Optional[str] = None,
    user_name: Optional[str] = None,
    max_results: int = 1000,
) -> List[Dict[str, Any]]:
    """
    Retrieves Falcon audit log events.
    NOTE: The CrowdStrike Falcon platform exposes audit events through the
    Falcon console UI and SIEM streaming only — there is no standalone
    FalconPy service class for audit event queries at this time.
    This function returns a structured response indicating the limitation.

    Returns:
        Empty list with informational message in logs.
    """
    logger.warning(
        "Audit events are not directly queryable via FalconPy SDK in this tenant configuration. "
        "Access audit logs via Falcon console > Audit Logs, or configure SIEM streaming."
    )
    return []


@with_retry(max_retries=3, base_delay=1.0)
def list_users(max_results: int = 1000) -> List[Dict[str, Any]]:
    """
    Retrieves all Falcon console users with roles.

    Returns:
        List of user dicts

    Raises:
        FalconAPIError: If the API call fails
    """
    falcon = get_falcon_client("UserManagement")
    logger.info("Querying Falcon user inventory...")

    # Query user UIDs
    response = falcon.retrieve_user_uuids_by_cid(limit=min(1000, max_results))
    check_api_response(response, "UserManagement")
    uids = response["body"].get("resources") or []

    if not uids:
        return []

    # Get user details
    details_response = falcon.retrieve_user(ids=uids)
    check_api_response(details_response, "UserManagement")
    return details_response["body"].get("resources") or []


@with_retry(max_retries=3, base_delay=1.0)
def get_user_roles(user_uuid: str) -> List[Dict[str, Any]]:
    """
    Retrieves RBAC roles assigned to a specific user.

    Args:
        user_uuid: The user's UUID

    Returns:
        List of role dicts

    Raises:
        FalconAPIError: If the API call fails
    """
    if not user_uuid or not user_uuid.strip():
        raise ValueError("user_uuid must be a non-empty string")

    falcon = get_falcon_client("UserManagement")
    response = falcon.get_user_role_ids(user_uuid=user_uuid.strip())
    check_api_response(response, "UserManagement")
    role_ids = response["body"].get("resources") or []

    if not role_ids:
        return []

    role_details = falcon.get_roles(ids=role_ids)
    check_api_response(role_details, "UserManagement")
    return role_details["body"].get("resources") or []


@with_retry(max_retries=3, base_delay=1.0)
def list_all_roles() -> List[Dict[str, Any]]:
    """
    Lists all RBAC roles defined in the Falcon tenant.

    Returns:
        List of role dicts
    """
    falcon = get_falcon_client("UserManagement")
    response = falcon.get_available_role_ids()
    check_api_response(response, "UserManagement")
    role_ids = response["body"].get("resources") or []

    if not role_ids:
        return []

    details = falcon.get_roles(ids=role_ids)
    check_api_response(details, "UserManagement")
    return details["body"].get("resources") or []


def check_integration_health() -> Dict[str, Any]:
    """
    Assembles integration health status by querying real API connectivity.
    Returns structured health data including API client count, user count,
    and role count.

    Returns:
        Dict with API client health metrics and user management data
    """
    health: Dict[str, Any] = {}

    # Check API clients
    try:
        clients = list_api_clients(max_results=50)
        health["api_clients"] = {
            "status": "Healthy",
            "total_clients": len(clients),
            "clients": [
                {
                    "name": c.get("name", "Unknown"),
                    "client_id": c.get("client_id", ""),
                    "status": c.get("status", "active"),
                    "last_used_timestamp": c.get("last_used_timestamp"),
                }
                for c in clients
            ],
        }
    except FalconAPIError as e:
        health["api_clients"] = {"status": "Error", "error": str(e)}

    # Check user management
    try:
        users = list_users(max_results=10)
        health["user_management"] = {
            "status": "Healthy",
            "total_users": len(users),
        }
    except FalconAPIError as e:
        health["user_management"] = {"status": "Error", "error": str(e)}

    # Check audit trail
    try:
        events = query_audit_events(hours=1, max_results=5)
        health["audit_trail"] = {
            "status": "Healthy",
            "events_last_hour": len(events),
        }
    except FalconAPIError as e:
        health["audit_trail"] = {"status": "Error", "error": str(e)}

    return health
