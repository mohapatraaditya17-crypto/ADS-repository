"""
CrowdStrike Falcon Identity Protection Retrieval Module
========================================================
Retrieves real identity alert and risk data from CrowdStrike Falcon
Identity Protection using the IdentityProtection service class (GraphQL API).

All functions are strictly read-only and return live API data.
No mock or fallback data is generated.
"""
import logging
import json
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional
from app.tools.crowdstrike.client_factory import (
    get_falcon_client,
    check_api_response,
    with_retry,
    FalconAPIError,
)

logger = logging.getLogger("crowdstrike_identity")

# GraphQL queries for Identity Protection API
IDENTITY_ALERTS_QUERY = """
query IdentityAlerts($filter: String, $first: Int, $after: String) {
  entities(filter: $filter, first: $first, after: $after) {
    nodes {
      primaryDisplayName
      secondaryDisplayName
      type
      riskScore
      riskScoreSeverity
      roles {
        displayName
        isPrimary
      }
      recentAlerts {
        timestamp
        alertType
        severity
        description
        status
      }
    }
    pageInfo {
      hasNextPage
      endCursor
    }
  }
}
"""

IDENTITY_TIMELINE_QUERY = """
query IdentityTimeline($filter: String, $first: Int) {
  timelineEvents(filter: $filter, first: $first) {
    nodes {
      timestamp
      eventType
      severity
      description
      entityType
      entityDisplayName
      sourceIP
      destinationIP
    }
  }
}
"""


@with_retry(max_retries=3, base_delay=1.0)
def query_identity_alerts(
    hours: int = 24,
    severity: Optional[str] = None,
    alert_type: Optional[str] = None,
    max_results: int = 1000,
) -> List[Dict[str, Any]]:
    """
    Retrieves identity-based alerts from Falcon Identity Protection.
    Uses the GraphQL API endpoint.

    Args:
        hours: Lookback window in hours
        severity: Optional severity filter e.g. "HIGH", "CRITICAL"
        alert_type: Optional alert type filter e.g. "LATERAL_MOVEMENT",
                    "CREDENTIAL_BASED", "KERBEROASTING"
        max_results: Maximum alerts to return

    Returns:
        List of identity alert dicts

    Raises:
        FalconAPIError: If the API call fails
    """
    try:
        falcon = get_falcon_client("IdentityProtection")
    except Exception as e:
        raise FalconAPIError(
            service="IdentityProtection",
            status_code=0,
            errors=[f"Identity Protection service unavailable: {e}"],
            scope_hint="Identity Protection: Read",
        )

    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    filter_parts = [f"timestamp >= '{since.strftime('%Y-%m-%dT%H:%M:%SZ')}'"]

    if severity:
        filter_parts.append(f"severity == '{severity.upper()}'")
    if alert_type:
        filter_parts.append(f"alertType == '{alert_type.upper()}'")

    gql_filter = " AND ".join(filter_parts)
    logger.info(f"Querying Identity Protection alerts with filter: {gql_filter!r}")

    try:
        all_alerts: List[Dict[str, Any]] = []
        after_cursor: Optional[str] = None

        while len(all_alerts) < max_results:
            variables: Dict[str, Any] = {
                "filter": gql_filter,
                "first": min(1000, max_results - len(all_alerts)),
            }
            if after_cursor:
                variables["after"] = after_cursor

            response = falcon.graphql(query=IDENTITY_ALERTS_QUERY, variables=variables)
            check_api_response(response, "IdentityProtection")

            data = response["body"].get("data", {})
            entities = data.get("entities", {})
            nodes = entities.get("nodes", [])
            all_alerts.extend(nodes)

            page_info = entities.get("pageInfo", {})
            if not page_info.get("hasNextPage"):
                break
            after_cursor = page_info.get("endCursor")

        return all_alerts[:max_results]

    except FalconAPIError:
        raise
    except Exception as e:
        raise FalconAPIError(
            service="IdentityProtection",
            status_code=0,
            errors=[f"GraphQL query failed: {e}"],
            scope_hint="Identity Protection: Read",
        )


@with_retry(max_retries=3, base_delay=1.0)
def get_identity_risk_scores(
    min_score: float = 70.0,
    max_results: int = 1000,
) -> List[Dict[str, Any]]:
    """
    Retrieves identities with elevated risk scores from Falcon Identity Protection.

    Args:
        min_score: Minimum risk score threshold (0-100)
        max_results: Maximum results to return

    Returns:
        List of high-risk identity dicts with scores and recent alerts

    Raises:
        FalconAPIError: If the API call fails
    """
    try:
        falcon = get_falcon_client("IdentityProtection")
    except Exception as e:
        raise FalconAPIError(
            service="IdentityProtection",
            status_code=0,
            errors=[f"Identity Protection service unavailable: {e}"],
            scope_hint="Identity Protection: Read",
        )

    gql_filter = f"riskScore >= {int(min_score)}"
    logger.info(f"Querying high-risk identities with filter: {gql_filter!r}")

    try:
        variables = {"filter": gql_filter, "first": min(1000, max_results)}
        response = falcon.graphql(query=IDENTITY_ALERTS_QUERY, variables=variables)
        check_api_response(response, "IdentityProtection")

        data = response["body"].get("data", {})
        return data.get("entities", {}).get("nodes", [])[:max_results]

    except FalconAPIError:
        raise
    except Exception as e:
        raise FalconAPIError(
            service="IdentityProtection",
            status_code=0,
            errors=[f"Risk score query failed: {e}"],
            scope_hint="Identity Protection: Read",
        )


@with_retry(max_retries=3, base_delay=1.0)
def get_compromised_accounts(hours: int = 168, max_results: int = 1000) -> List[Dict[str, Any]]:
    """
    Retrieves accounts flagged as potentially compromised based on
    high-risk identity alerts and scores.

    Args:
        hours: Lookback window in hours (default 7 days)
        max_results: Maximum accounts to return

    Returns:
        List of compromised account identity dicts
    """
    alerts = query_identity_alerts(
        hours=hours,
        severity="HIGH",
        max_results=max_results,
    )
    # Filter to accounts with recent alerts indicating compromise
    compromised = [
        a for a in alerts
        if a.get("riskScoreSeverity") in ("CRITICAL", "HIGH")
        or any(
            alert.get("severity") in ("HIGH", "CRITICAL")
            for alert in a.get("recentAlerts", [])
        )
    ]
    return compromised[:max_results]


@with_retry(max_retries=3, base_delay=1.0)
def get_identity_timeline(
    entity_name: Optional[str] = None,
    hours: int = 24,
    max_results: int = 1000,
) -> List[Dict[str, Any]]:
    """
    Retrieves the identity activity timeline from Falcon Identity Protection.

    Args:
        entity_name: Optional entity name filter
        hours: Lookback window in hours
        max_results: Maximum timeline events to return

    Returns:
        List of timeline event dicts
    """
    try:
        falcon = get_falcon_client("IdentityProtection")
    except Exception as e:
        raise FalconAPIError(
            service="IdentityProtection",
            status_code=0,
            errors=[f"Identity Protection service unavailable: {e}"],
            scope_hint="Identity Protection: Read",
        )

    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    filter_parts = [f"timestamp >= '{since.strftime('%Y-%m-%dT%H:%M:%SZ')}'"]
    if entity_name:
        filter_parts.append(f"entityDisplayName == '{entity_name}'")

    gql_filter = " AND ".join(filter_parts)
    logger.info(f"Querying identity timeline with filter: {gql_filter!r}")

    try:
        variables = {"filter": gql_filter, "first": min(1000, max_results)}
        response = falcon.graphql(query=IDENTITY_TIMELINE_QUERY, variables=variables)
        check_api_response(response, "IdentityProtection")
        data = response["body"].get("data", {})
        return data.get("timelineEvents", {}).get("nodes", [])[:max_results]
    except FalconAPIError:
        raise
    except Exception as e:
        raise FalconAPIError(
            service="IdentityProtection",
            status_code=0,
            errors=[f"Timeline query failed: {e}"],
            scope_hint="Identity Protection: Read",
        )
