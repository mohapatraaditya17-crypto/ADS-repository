"""
CrowdStrike Falcon Executive Metrics Aggregation Module
========================================================
Aggregates real data from multiple Falcon API modules to produce
executive-level KPIs, threat trends, and SOC metrics including
MTTD, MTTR, top threats, and coverage statistics.

All functions are strictly read-only and return live API data.
No mock or fallback data is generated.
"""
import logging
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional
from app.tools.crowdstrike.client_factory import FalconAPIError

logger = logging.getLogger("crowdstrike_metrics")


def get_executive_metrics(hours: int = 24) -> Dict[str, Any]:
    """
    Assembles a complete executive metrics dashboard from real Falcon data.
    Calls multiple modules and aggregates KPIs.

    Args:
        hours: Lookback window in hours

    Returns:
        Dict with all executive KPIs and trend data

    Raises:
        Does not raise — individual module failures are captured as error messages
    """
    metrics: Dict[str, Any] = {
        "period_hours": hours,
        "as_of": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "detections": {},
        "incidents": {},
        "sensor_coverage": {},
        "vulnerabilities": {},
        "top_threats": {},
        "errors": [],
    }

    # Detection metrics
    try:
        from app.tools.crowdstrike.detections import (
            query_recent_detections,
            get_detection_count_by_severity,
        )
        severity_counts = get_detection_count_by_severity(hours=hours)
        total_detections = sum(severity_counts.values())
        metrics["detections"] = {
            "total": total_detections,
            "by_severity": severity_counts,
        }
    except FalconAPIError as e:
        logger.warning(f"Detection metrics failed: {e}")
        metrics["errors"].append(f"Detections: {str(e)}")

    # Incident metrics
    try:
        from app.tools.crowdstrike.incidents import get_incident_count_by_period
        inc_data = get_incident_count_by_period(hours=hours)
        metrics["incidents"] = {
            "total": inc_data["total"],
            "status_breakdown": inc_data["status_breakdown"],
            "avg_fine_score": inc_data["avg_score"],
        }
    except FalconAPIError as e:
        logger.warning(f"Incident metrics failed: {e}")
        metrics["errors"].append(f"Incidents: {str(e)}")

    # Sensor coverage
    try:
        from app.tools.crowdstrike.sensor import get_sensor_coverage
        metrics["sensor_coverage"] = get_sensor_coverage()
    except FalconAPIError as e:
        logger.warning(f"Sensor coverage failed: {e}")
        metrics["errors"].append(f"Sensor Coverage: {str(e)}")

    # Vulnerability summary
    try:
        from app.tools.crowdstrike.spotlight import (
            get_vuln_summary_by_severity,
            get_kev_vulnerabilities,
        )
        vuln_by_severity = get_vuln_summary_by_severity()
        kev_count = len(get_kev_vulnerabilities(max_results=1000))
        metrics["vulnerabilities"] = {
            "by_severity": vuln_by_severity,
            "kev_count": kev_count,
            "total_open": sum(vuln_by_severity.values()),
        }
    except FalconAPIError as e:
        logger.warning(f"Vulnerability metrics failed: {e}")
        metrics["errors"].append(f"Vulnerabilities: {str(e)}")

    # Top threats (from detection behaviors)
    try:
        metrics["top_threats"] = get_top_threats(hours=hours)
    except Exception as e:
        logger.warning(f"Top threats analysis failed: {e}")
        metrics["errors"].append(f"Top Threats: {str(e)}")

    return metrics


def get_top_threats(hours: int = 24, top_n: int = 10) -> Dict[str, Any]:
    """
    Analyzes detections to identify the most prevalent threats by
    technique, tactic, and affected host.

    Args:
        hours: Lookback window in hours
        top_n: Number of top items to return per category

    Returns:
        Dict with top techniques, tactics, hosts, and usernames
    """
    from app.tools.crowdstrike.detections import query_recent_detections

    detections = query_recent_detections(hours=hours, max_results=2000)

    technique_counts: Dict[str, int] = {}
    tactic_counts: Dict[str, int] = {}
    host_counts: Dict[str, int] = {}
    user_counts: Dict[str, int] = {}

    for det in detections:
        hostname = det.get("device", {}).get("hostname", "Unknown")
        host_counts[hostname] = host_counts.get(hostname, 0) + 1

        for b in det.get("behaviors", []):
            technique = b.get("technique")
            if technique:
                technique_counts[technique] = technique_counts.get(technique, 0) + 1

            tactic = b.get("tactic")
            if tactic:
                tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1

            user = b.get("user_name")
            if user:
                user_counts[user] = user_counts.get(user, 0) + 1

    def top_n_items(d: Dict[str, int]) -> List[Dict[str, Any]]:
        return [
            {"name": k, "count": v}
            for k, v in sorted(d.items(), key=lambda x: x[1], reverse=True)[:top_n]
        ]

    return {
        "top_techniques": top_n_items(technique_counts),
        "top_tactics": top_n_items(tactic_counts),
        "top_hosts": top_n_items(host_counts),
        "top_users": top_n_items(user_counts),
    }


def get_mttd(hours: int = 168) -> Dict[str, Any]:
    """
    Calculates Mean Time to Detect (MTTD) from detection timestamps.
    MTTD = average time between first behavior and detection creation.

    Args:
        hours: Lookback window in hours (default 7 days)

    Returns:
        Dict with MTTD statistics in seconds and human-readable format
    """
    from app.tools.crowdstrike.detections import query_recent_detections

    detections = query_recent_detections(hours=hours, max_results=2000)
    deltas: List[float] = []

    for det in detections:
        created = det.get("created_timestamp")
        first_behavior = det.get("first_behavior")
        if created and first_behavior:
            try:
                t_created = datetime.fromisoformat(
                    created.replace("Z", "+00:00")
                )
                t_first = datetime.fromisoformat(
                    first_behavior.replace("Z", "+00:00")
                )
                delta = (t_created - t_first).total_seconds()
                if delta >= 0:
                    deltas.append(delta)
            except Exception:
                pass

    if not deltas:
        return {
            "mttd_seconds": None,
            "mttd_human": "Insufficient data",
            "sample_size": 0,
        }

    avg = sum(deltas) / len(deltas)
    return {
        "mttd_seconds": round(avg, 2),
        "mttd_human": _seconds_to_human(avg),
        "sample_size": len(deltas),
        "min_seconds": round(min(deltas), 2),
        "max_seconds": round(max(deltas), 2),
    }


def get_mttr(hours: int = 168) -> Dict[str, Any]:
    """
    Calculates Mean Time to Respond (MTTR) from incident timestamps.
    MTTR = average time from incident creation to resolution.

    Args:
        hours: Lookback window in hours (default 7 days)

    Returns:
        Dict with MTTR statistics
    """
    from app.tools.crowdstrike.incidents import query_incidents

    incidents = query_incidents(hours=hours, max_results=500)
    deltas: List[float] = []

    for inc in incidents:
        created = inc.get("created_timestamp")
        resolved = inc.get("end_time")
        if created and resolved:
            try:
                t_created = datetime.fromisoformat(
                    created.replace("Z", "+00:00")
                )
                t_resolved = datetime.fromisoformat(
                    resolved.replace("Z", "+00:00")
                )
                delta = (t_resolved - t_created).total_seconds()
                if delta >= 0:
                    deltas.append(delta)
            except Exception:
                pass

    if not deltas:
        return {
            "mttr_seconds": None,
            "mttr_human": "Insufficient data (no resolved incidents in window)",
            "sample_size": 0,
        }

    avg = sum(deltas) / len(deltas)
    return {
        "mttr_seconds": round(avg, 2),
        "mttr_human": _seconds_to_human(avg),
        "sample_size": len(deltas),
    }


def get_mitre_coverage(hours: int = 720) -> Dict[str, int]:
    """
    Returns MITRE ATT&CK technique coverage detected in the environment
    over the specified period.

    Args:
        hours: Lookback window (default 30 days)

    Returns:
        Dict mapping technique_id to detection count
    """
    from app.tools.crowdstrike.detections import query_recent_detections

    detections = query_recent_detections(hours=hours, max_results=5000)
    coverage: Dict[str, int] = {}

    for det in detections:
        for b in det.get("behaviors", []):
            tid = b.get("technique_id")
            if tid:
                coverage[tid] = coverage.get(tid, 0) + 1

    return dict(sorted(coverage.items(), key=lambda x: x[1], reverse=True))


def _seconds_to_human(seconds: float) -> str:
    """Converts seconds to a human-readable duration string."""
    if seconds < 60:
        return f"{int(seconds)} seconds"
    elif seconds < 3600:
        return f"{int(seconds // 60)} minutes"
    elif seconds < 86400:
        hours = int(seconds // 3600)
        mins = int((seconds % 3600) // 60)
        return f"{hours} hours {mins} minutes"
    else:
        days = int(seconds // 86400)
        hours = int((seconds % 86400) // 3600)
        return f"{days} days {hours} hours"
