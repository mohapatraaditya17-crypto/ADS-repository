"""
CrowdStrike Falcon Spotlight Vulnerability Retrieval Module
============================================================
Retrieves real vulnerability data from CrowdStrike Falcon Spotlight
using the SpotlightVulnerabilities service class.

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

logger = logging.getLogger("crowdstrike_spotlight")

BATCH_SIZE = 400  # Spotlight recommends up to 400 IDs per batch
VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"}
VALID_STATUSES = {"open", "reopen", "closed"}


def _paginate_vulnerabilities(
    falcon,
    fql: str,
    max_results: int = 5000,
) -> List[str]:
    """
    Paginates through vulnerability query results.
    Spotlight uses an 'after' cursor for pagination.
    """
    all_ids: List[str] = []
    after_cursor: Optional[str] = None
    page_size = min(400, max_results)

    while True:
        kwargs: Dict[str, Any] = {
            "filter": fql,
            "sort": "updated_timestamp.desc",
            "limit": page_size,
        }
        if after_cursor:
            kwargs["after"] = after_cursor

        response = falcon.query_vulnerabilities(**kwargs)
        check_api_response(response, "SpotlightVulnerabilities")
        body = response["body"]
        resources = body.get("resources") or []
        all_ids.extend(resources)

        # Spotlight uses cursor pagination
        meta = body.get("meta", {})
        pagination = meta.get("pagination", {})
        after_cursor = pagination.get("after")

        if not resources or not after_cursor or len(all_ids) >= max_results:
            break

    return all_ids[:max_results]


@with_retry(max_retries=3, base_delay=1.0)
def query_vulnerabilities(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    cve_id: Optional[str] = None,
    aid: Optional[str] = None,
    is_kev: Optional[bool] = None,
    max_results: int = 1000,
) -> List[Dict[str, Any]]:
    """
    Queries CrowdStrike Spotlight for endpoint vulnerabilities.

    Args:
        severity: Filter by severity e.g. "CRITICAL", "HIGH", "MEDIUM", "LOW"
        status: Filter by status e.g. "open", "closed", "reopen"
        cve_id: Specific CVE ID to search for e.g. "CVE-2023-1234"
        aid: Filter by agent/device ID
        is_kev: If True, only return CISA Known Exploited Vulnerabilities
        max_results: Maximum vulnerabilities to return

    Returns:
        List of vulnerability detail dicts

    Raises:
        FalconAPIError: If the API call fails
    """
    falcon = get_falcon_client("SpotlightVulnerabilities")
    fql_parts: List[str] = []

    if severity and severity.upper() in VALID_SEVERITIES:
        fql_parts.append(f"cve.severity:'{severity.upper()}'")
    if status and status.lower() in VALID_STATUSES:
        fql_parts.append(f"status:'{status.lower()}'")
    if cve_id:
        fql_parts.append(f"cve.id:'{cve_id.upper()}'")
    if aid:
        fql_parts.append(f"aid:'{aid}'")
    if is_kev is True:
        fql_parts.append("cve.is_kev:'true'")

    fql = " + ".join(fql_parts)
    if not fql:
        fql = "status:'open'"  # Default to open vulnerabilities

    logger.info(f"Querying Spotlight vulnerabilities with FQL: {fql!r}")

    vuln_ids = _paginate_vulnerabilities(falcon, fql, max_results=max_results)
    if not vuln_ids:
        logger.info("No vulnerabilities found matching the query.")
        return []

    logger.info(f"Retrieving details for {len(vuln_ids)} vulnerabilities...")
    all_details: List[Dict[str, Any]] = []

    for i in range(0, len(vuln_ids), BATCH_SIZE):
        batch = vuln_ids[i : i + BATCH_SIZE]
        response = falcon.get_vulnerabilities(ids=batch)
        check_api_response(response, "SpotlightVulnerabilities")
        all_details.extend(response["body"].get("resources") or [])

    return all_details


@with_retry(max_retries=3, base_delay=1.0)
def get_vulnerability_details(vuln_id: str) -> Dict[str, Any]:
    """
    Retrieves full details for a single vulnerability.

    Args:
        vuln_id: Spotlight vulnerability ID

    Returns:
        Vulnerability detail dict

    Raises:
        FalconAPIError: If not found or API call fails
    """
    if not vuln_id or not vuln_id.strip():
        raise ValueError("vuln_id must be a non-empty string")

    falcon = get_falcon_client("SpotlightVulnerabilities")
    response = falcon.get_vulnerabilities(ids=[vuln_id.strip()])
    check_api_response(response, "SpotlightVulnerabilities")
    resources = response["body"].get("resources") or []
    if not resources:
        raise FalconAPIError(
            service="SpotlightVulnerabilities",
            status_code=404,
            errors=[f"Vulnerability '{vuln_id}' not found."],
        )
    return resources[0]


@with_retry(max_retries=3, base_delay=1.0)
def get_vuln_summary_by_severity() -> Dict[str, int]:
    """
    Returns vulnerability counts grouped by severity.
    Used for executive metrics and reports.

    Returns:
        Dict mapping severity to count e.g. {"CRITICAL": 15, "HIGH": 87}
    """
    falcon = get_falcon_client("SpotlightVulnerabilities")
    counts: Dict[str, int] = {}

    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        try:
            fql = f"cve.severity:'{severity}' + status:'open'"
            response = falcon.query_vulnerabilities(filter=fql, limit=1)
            check_api_response(response, "SpotlightVulnerabilities")
            total = (
                response["body"]
                .get("meta", {})
                .get("pagination", {})
                .get("total", 0)
            )
            counts[severity] = total
        except FalconAPIError as e:
            logger.warning(f"Failed to get vuln count for severity {severity}: {e}")
            counts[severity] = 0

    return counts


@with_retry(max_retries=3, base_delay=1.0)
def get_top_vulnerable_hosts(max_results: int = 10) -> List[Dict[str, Any]]:
    """
    Returns the hosts with the most open critical/high vulnerabilities.

    Args:
        max_results: Number of top hosts to return

    Returns:
        List of dicts with hostname and vulnerability counts
    """
    vulns = query_vulnerabilities(severity="CRITICAL", status="open", max_results=5000)
    host_counts: Dict[str, int] = {}
    for v in vulns:
        hostname = v.get("host_info", {}).get("hostname", "Unknown")
        host_counts[hostname] = host_counts.get(hostname, 0) + 1

    sorted_hosts = sorted(host_counts.items(), key=lambda x: x[1], reverse=True)
    return [
        {"hostname": h, "critical_vuln_count": c}
        for h, c in sorted_hosts[:max_results]
    ]


@with_retry(max_retries=3, base_delay=1.0)
def get_kev_vulnerabilities(max_results: int = 1000) -> List[Dict[str, Any]]:
    """
    Retrieves open CISA Known Exploited Vulnerabilities (KEV) affecting endpoints.

    Returns:
        List of KEV vulnerability dicts
    """
    return query_vulnerabilities(is_kev=True, status="open", max_results=max_results)
