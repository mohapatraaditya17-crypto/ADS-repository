"""
CrowdStrike Falcon User Management Retrieval Module
====================================================
Retrieves real user and identity data from CrowdStrike Falcon using the
UserManagement service class.

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

logger = logging.getLogger("crowdstrike_users")


@with_retry(max_retries=3, base_delay=1.0)
def list_users(max_results: int = 1000) -> List[Dict[str, Any]]:
    """
    Retrieves all Falcon console users.

    Returns:
        List of user dicts with uid, username, email, first_name, last_name

    Raises:
        FalconAPIError: If the API call fails
    """
    falcon = get_falcon_client("UserManagement")
    logger.info("Listing all Falcon users...")

    response = falcon.retrieve_user_uuids_by_cid(limit=min(1000, max_results))
    check_api_response(response, "UserManagement")
    uids = response["body"].get("resources") or []

    if not uids:
        logger.info("No users found.")
        return []

    details = falcon.retrieve_user(ids=uids)
    check_api_response(details, "UserManagement")
    return details["body"].get("resources") or []


@with_retry(max_retries=3, base_delay=1.0)
def get_user_details(user_uuid: str) -> Dict[str, Any]:
    """
    Retrieves full details for a specific user by UUID.

    Args:
        user_uuid: The user's UUID

    Returns:
        User detail dict

    Raises:
        FalconAPIError: If the user is not found or API call fails
    """
    if not user_uuid or not user_uuid.strip():
        raise ValueError("user_uuid must be a non-empty string")

    falcon = get_falcon_client("UserManagement")
    response = falcon.retrieve_user(ids=[user_uuid.strip()])
    check_api_response(response, "UserManagement")
    resources = response["body"].get("resources") or []
    if not resources:
        raise FalconAPIError(
            service="UserManagement",
            status_code=404,
            errors=[f"User '{user_uuid}' not found."],
        )
    return resources[0]


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
    role_id_response = falcon.get_user_role_ids(user_uuid=user_uuid.strip())
    check_api_response(role_id_response, "UserManagement")
    role_ids = role_id_response["body"].get("resources") or []

    if not role_ids:
        return []

    role_details = falcon.get_roles(ids=role_ids)
    check_api_response(role_details, "UserManagement")
    return role_details["body"].get("resources") or []


@with_retry(max_retries=3, base_delay=1.0)
def search_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    """
    Searches for a user by their email address.

    Args:
        email: User email address

    Returns:
        User detail dict or None if not found

    Raises:
        FalconAPIError: If the API call fails
    """
    users = list_users()
    email_lower = email.strip().lower()
    for user in users:
        if user.get("uid", "").lower() == email_lower:
            return user
    return None


@with_retry(max_retries=3, base_delay=1.0)
def list_all_roles() -> List[Dict[str, Any]]:
    """
    Lists all available RBAC roles in the tenant.

    Returns:
        List of role definition dicts
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


def get_users_with_roles() -> List[Dict[str, Any]]:
    """
    Returns all users enriched with their role assignments.

    Returns:
        List of user dicts each containing a 'roles' field
    """
    users = list_users()
    enriched: List[Dict[str, Any]] = []

    for user in users:
        uid = user.get("uuid", "")
        try:
            roles = get_user_roles(uid) if uid else []
        except FalconAPIError:
            roles = []
        enriched.append({**user, "roles": roles})

    return enriched
