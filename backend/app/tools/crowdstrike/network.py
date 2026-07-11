"""
CrowdStrike Falcon Network Event Retrieval Module
==================================================
Extracts real network activity data from CrowdStrike Falcon detection and
incident behaviors. Network data includes DNS requests, TCP/UDP connections,
HTTP requests, and domain communications observed during detections.

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

logger = logging.getLogger("crowdstrike_network")


def extract_network_events_from_behaviors(
    behaviors: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Extracts network-related fields from detection behavior objects.
    Detection behaviors contain embedded network activity context.

    Args:
        behaviors: List of behavior dicts from Detects/Incidents APIs

    Returns:
        List of network event dicts with source, destination, protocol info
    """
    events: List[Dict[str, Any]] = []

    for b in behaviors:
        # Network fields embedded in behaviors
        network_accesses = b.get("network_accesses", [])
        for na in network_accesses:
            events.append({
                "type": "network_connection",
                "behavior_id": b.get("behavior_id"),
                "tactic": b.get("tactic"),
                "technique": b.get("technique"),
                "local_address": na.get("local_address"),
                "local_port": na.get("local_port"),
                "remote_address": na.get("remote_address"),
                "remote_port": na.get("remote_port"),
                "protocol": na.get("protocol"),
                "access_type": na.get("access_type"),
                "connection_direction": na.get("connection_direction"),
            })

        # DNS requests
        dns_requests = b.get("dns_requests", [])
        for dns in dns_requests:
            events.append({
                "type": "dns_request",
                "behavior_id": b.get("behavior_id"),
                "domain": dns.get("domain"),
                "address": dns.get("address"),
                "request_outcome": dns.get("request_outcome"),
            })

        # Document requests (HTTP/S)
        doc_requests = b.get("document_signature", {})
        if doc_requests:
            events.append({
                "type": "document_signature",
                "behavior_id": b.get("behavior_id"),
                "document_name": doc_requests.get("document_name"),
                "document_description": doc_requests.get("document_description"),
            })

    return events


@with_retry(max_retries=3, base_delay=1.0)
def get_network_events_for_detection(
    detection: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """
    Retrieves all network events associated with a specific detection.

    Args:
        detection: A detection summary dict from the Detects API

    Returns:
        List of network event dicts
    """
    behaviors = detection.get("behaviors", [])
    if not behaviors:
        return []
    return extract_network_events_from_behaviors(behaviors)


@with_retry(max_retries=3, base_delay=1.0)
def get_network_events_for_incident(incident_id: str) -> List[Dict[str, Any]]:
    """
    Retrieves all network events associated with a specific incident
    by pulling incident behaviors and extracting network data.

    Args:
        incident_id: Falcon incident ID

    Returns:
        List of network event dicts

    Raises:
        FalconAPIError: If the API call fails
    """
    from app.tools.crowdstrike.incidents import get_incident_behaviors
    behaviors = get_incident_behaviors(incident_id)
    return extract_network_events_from_behaviors(behaviors)


@with_retry(max_retries=3, base_delay=1.0)
def get_dns_requests_for_detection(
    detection: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """
    Extracts only DNS request events from a detection's behaviors.

    Args:
        detection: Detection dict from the Detects API

    Returns:
        List of DNS request event dicts
    """
    all_events = get_network_events_for_detection(detection)
    return [e for e in all_events if e.get("type") == "dns_request"]


@with_retry(max_retries=3, base_delay=1.0)
def get_external_connections(
    detections: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Extracts all external (public IP) network connections from a list of detections.
    Useful for identifying C2 beacon activity and data exfiltration.

    Args:
        detections: List of detection dicts from the Detects API

    Returns:
        List of external connection event dicts
    """
    external: List[Dict[str, Any]] = []
    seen: set = set()

    for det in detections:
        events = get_network_events_for_detection(det)
        for ev in events:
            if ev.get("type") == "network_connection":
                remote_ip = ev.get("remote_address", "")
                if remote_ip and not _is_private_ip(remote_ip):
                    key = f"{remote_ip}:{ev.get('remote_port')}"
                    if key not in seen:
                        seen.add(key)
                        ev["detection_id"] = det.get("detection_id")
                        ev["hostname"] = det.get("device", {}).get("hostname")
                        external.append(ev)

    return external


def _is_private_ip(ip: str) -> bool:
    """
    Checks if an IP address belongs to a private/RFC1918 range.
    """
    try:
        parts = [int(p) for p in ip.split(".")]
        if len(parts) != 4:
            return False
        if parts[0] == 10:
            return True
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True
        if parts[0] == 192 and parts[1] == 168:
            return True
        if parts[0] == 127:
            return True
    except Exception:
        pass
    return False
