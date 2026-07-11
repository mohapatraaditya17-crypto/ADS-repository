"""
CrowdStrike Falcon Cross-Module Correlation Engine
===================================================
Correlates data across multiple Falcon API modules to build unified
investigation objects, attack paths, and comprehensive incident pictures.

This is a pure logic module — it calls other retrieval modules but makes
no direct API calls itself.

All operations are strictly read-only.
"""
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from app.tools.crowdstrike.client_factory import FalconAPIError

logger = logging.getLogger("crowdstrike_correlation")


def build_unified_detection_investigation(
    detection: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Given a detection summary dict, builds a fully correlated investigation
    object by fetching associated host, process, network, and intel data.

    Args:
        detection: Detection dict from query_recent_detections()

    Returns:
        Unified investigation dict with all correlated data
    """
    from app.tools.crowdstrike.processes import build_process_tree_from_behaviors
    from app.tools.crowdstrike.network import (
        get_network_events_for_detection,
        get_dns_requests_for_detection,
    )

    investigation: Dict[str, Any] = {
        "detection": detection,
        "host": None,
        "process_tree": [],
        "network_events": [],
        "dns_requests": [],
        "ioc_pivots": [],
        "related_incidents": [],
        "correlation_timestamp": datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
    }

    # Enrich with host data
    device = detection.get("device", {})
    host_id = device.get("device_id")
    if host_id:
        try:
            from app.tools.crowdstrike.hosts import get_host_details
            investigation["host"] = get_host_details(host_id)
        except FalconAPIError as e:
            logger.warning(f"Could not retrieve host details for {host_id}: {e}")
            investigation["host"] = device  # Use inline device data as fallback

    # Build process tree from behaviors
    behaviors = detection.get("behaviors", [])
    investigation["process_tree"] = build_process_tree_from_behaviors(behaviors)

    # Extract network events
    try:
        investigation["network_events"] = get_network_events_for_detection(detection)
        investigation["dns_requests"] = get_dns_requests_for_detection(detection)
    except Exception as e:
        logger.warning(f"Network event extraction failed: {e}")

    # IOC pivot — look up hashes from behaviors
    for behavior in behaviors:
        sha256 = behavior.get("sha256")
        if sha256:
            try:
                from app.tools.crowdstrike.intel import lookup_ioc
                intel = lookup_ioc("sha256", sha256)
                if intel.get("found") is not False:
                    investigation["ioc_pivots"].append(intel)
            except FalconAPIError as e:
                logger.warning(f"IOC pivot failed for hash {sha256}: {e}")

    # Find related incidents
    if host_id:
        try:
            from app.tools.crowdstrike.incidents import query_incidents_by_host
            investigation["related_incidents"] = query_incidents_by_host(
                device_id=host_id, hours=168
            )
        except FalconAPIError as e:
            logger.warning(f"Related incidents query failed: {e}")

    return investigation


def build_unified_incident_investigation(
    incident: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Given an incident dict, builds a fully correlated investigation object
    by fetching associated behaviors, hosts, users, and network events.

    Args:
        incident: Incident dict from query_incidents()

    Returns:
        Unified investigation dict
    """
    from app.tools.crowdstrike.incidents import get_incident_behaviors
    from app.tools.crowdstrike.network import extract_network_events_from_behaviors
    from app.tools.crowdstrike.processes import build_process_tree_from_behaviors

    incident_id = incident.get("incident_id") or incident.get("id", "")
    investigation: Dict[str, Any] = {
        "incident": incident,
        "behaviors": [],
        "hosts": [],
        "process_tree": [],
        "network_events": [],
        "related_detections": [],
        "correlation_timestamp": datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
    }

    # Get behaviors
    if incident_id:
        try:
            behaviors = get_incident_behaviors(incident_id)
            investigation["behaviors"] = behaviors
            investigation["process_tree"] = build_process_tree_from_behaviors(behaviors)
            investigation["network_events"] = extract_network_events_from_behaviors(behaviors)
        except FalconAPIError as e:
            logger.warning(f"Behavior retrieval failed for incident {incident_id}: {e}")

    # Enrich hosts
    host_ids = [h.get("device_id") for h in incident.get("hosts", []) if h.get("device_id")]
    for host_id in host_ids[:5]:  # Limit to 5 hosts for performance
        try:
            from app.tools.crowdstrike.hosts import get_host_details
            investigation["hosts"].append(get_host_details(host_id))
        except FalconAPIError as e:
            logger.warning(f"Host enrichment failed for {host_id}: {e}")

    # Get related detections
    detect_ids = incident.get("detection_ids", [])
    if detect_ids:
        try:
            from app.tools.crowdstrike.detections import get_detection_details
            for did in detect_ids[:10]:  # Limit to 10
                try:
                    investigation["related_detections"].append(
                        get_detection_details(did)
                    )
                except FalconAPIError:
                    pass
        except Exception as e:
            logger.warning(f"Related detection retrieval failed: {e}")

    return investigation


def build_attack_path(investigation: Dict[str, Any]) -> Dict[str, Any]:
    """
    Builds a structured attack path from a unified investigation object.
    Maps behaviors to MITRE ATT&CK phases and creates an ordered timeline.

    Args:
        investigation: Unified investigation dict from build_unified_detection_investigation()
                       or build_unified_incident_investigation()

    Returns:
        Attack path dict with chronological timeline and MITRE mapping
    """
    attack_path: Dict[str, Any] = {
        "kill_chain": [],
        "mitre_techniques": {},
        "hosts_involved": [],
        "users_involved": [],
        "external_ips": [],
        "timeline": [],
    }

    # Extract from detection
    detection = investigation.get("detection") or {}
    behaviors = detection.get("behaviors", []) or investigation.get("behaviors", [])

    # Build MITRE mapping
    for b in behaviors:
        tactic = b.get("tactic")
        technique_id = b.get("technique_id")
        technique = b.get("technique")
        ts = b.get("timestamp") or b.get("created_timestamp")

        if tactic and tactic not in attack_path["kill_chain"]:
            attack_path["kill_chain"].append(tactic)

        if technique_id:
            attack_path["mitre_techniques"][technique_id] = {
                "technique": technique,
                "tactic": tactic,
                "description": b.get("description", ""),
            }

        if ts:
            attack_path["timeline"].append({
                "timestamp": ts,
                "event": technique or "Unknown",
                "tactic": tactic,
                "technique_id": technique_id,
                "process": b.get("filename"),
                "cmdline": b.get("cmdline"),
                "user": b.get("user_name"),
            })

    # Sort timeline chronologically
    attack_path["timeline"].sort(key=lambda x: x.get("timestamp") or "")

    # Hosts involved
    host = investigation.get("host") or {}
    if host.get("hostname"):
        attack_path["hosts_involved"].append(host.get("hostname"))

    for h in investigation.get("hosts", []):
        hn = h.get("hostname")
        if hn and hn not in attack_path["hosts_involved"]:
            attack_path["hosts_involved"].append(hn)

    # External IPs
    for net_ev in investigation.get("network_events", []):
        remote = net_ev.get("remote_address")
        if remote and remote not in attack_path["external_ips"]:
            attack_path["external_ips"].append(remote)

    return attack_path


def correlate_ioc(
    indicator_type: str,
    indicator_value: str,
    hours: int = 720,
) -> Dict[str, Any]:
    """
    Performs a complete IOC pivot: looks up the indicator in Falcon Intelligence
    and finds all related detections, incidents, and hosts.

    Args:
        indicator_type: IOC type e.g. "sha256", "domain", "ipv4"
        indicator_value: The indicator value
        hours: Lookback window for related detections (default 30 days)

    Returns:
        Dict with intel context, related detections, incidents, and hosts
    """
    result: Dict[str, Any] = {
        "indicator": {"type": indicator_type, "value": indicator_value},
        "intel": None,
        "related_detections": [],
        "related_incidents": [],
        "affected_hosts": [],
    }

    # Intel lookup
    try:
        from app.tools.crowdstrike.intel import lookup_ioc
        result["intel"] = lookup_ioc(indicator_type, indicator_value)
    except FalconAPIError as e:
        logger.warning(f"Intel lookup failed for IOC {indicator_value}: {e}")

    # Search detections containing this IOC
    try:
        from app.tools.crowdstrike.detections import query_recent_detections
        detections = query_recent_detections(hours=hours, max_results=1000)

        for det in detections:
            for b in det.get("behaviors", []):
                matched = (
                    (indicator_type == "sha256" and b.get("sha256") == indicator_value)
                    or (indicator_type == "domain" and indicator_value in str(b.get("dns_requests", "")))
                    or (indicator_type in ("ipv4", "ip_address") and indicator_value in str(b.get("network_accesses", "")))
                )
                if matched:
                    result["related_detections"].append(det.get("detection_id"))
                    host = det.get("device", {}).get("hostname")
                    if host and host not in result["affected_hosts"]:
                        result["affected_hosts"].append(host)
                    break
    except FalconAPIError as e:
        logger.warning(f"Detection search failed for IOC pivot: {e}")

    # Deduplicate
    result["related_detections"] = list(set(result["related_detections"]))

    return result
