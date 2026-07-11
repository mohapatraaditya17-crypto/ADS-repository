"""
SOC Report Generator Agent
===========================
Detects the requested report period from natural language, assembles
real data from all Falcon API modules, generates report files, and
streams the LLM-generated executive summary.

Supported periods: daily, weekly, monthly, quarterly, annual
"""
import logging
import os
import time
import re
from datetime import datetime, timezone
from typing import Generator, List, Dict, Any
from app.agents.llm import call_llm_stream
from app.tools.report_writer import generate_soc_report
from app.tools.crowdstrike.client_factory import FalconAPIError

logger = logging.getLogger("report_generator")

SYSTEM_PROMPT = """
You are the "Report Generator" agent for the Falcon AI Copilot. Your role is to
present the compiled SOC report data in a clear executive summary format.

CRITICAL INSTRUCTIONS:
1. Always state the report period and time window covered at the top.
2. Highlight the most critical findings in bold — total detections, incidents, KEV vulns.
3. Present KPIs (MTTD, MTTR, coverage %) as a prominent metric table.
4. Summarize top threats and affected hosts.
5. Always provide the download links for the generated files.
6. Note that all data is sourced from live CrowdStrike Falcon APIs.
7. Falcon AI Copilot operates in READ-ONLY mode. No resources were modified.
8. STRICT ANTI-HALLUCINATION RULE: If you are unable to answer a question or if the API returns an error or no data, DO NOT make up or hallucinate any data. You MUST return a clear statement explaining the reason (e.g., "couldn't reach server", "unable to verify", "API error", "no records found").

Format your response using Markdown with clear headings, tables, and bullet points.
"""

PERIOD_CONFIG = {
    "daily":     {"hours": 24,    "label": "Daily (Last 24 Hours)"},
    "weekly":    {"hours": 168,   "label": "Weekly (Last 7 Days)"},
    "monthly":   {"hours": 720,   "label": "Monthly (Last 30 Days)"},
    "quarterly": {"hours": 2160,  "label": "Quarterly (Last 90 Days)"},
    "annual":    {"hours": 8760,  "label": "Annual (Last 365 Days)"},
}


def _detect_report_period(query: str) -> str:
    """
    Detects the requested report period from natural-language query text.
    Returns a period key: "daily", "weekly", "monthly", "quarterly", "annual".
    Defaults to "daily" if no period is detected.
    """
    q = query.lower()

    # Annual
    if any(k in q for k in ["annual", "yearly", "year", "365"]):
        return "annual"

    # Quarterly
    if any(k in q for k in ["quarter", "quarterly", "q1", "q2", "q3", "q4", "90 day"]):
        return "quarterly"

    # Monthly
    if any(k in q for k in ["month", "monthly", "30 day", "last month"]):
        return "monthly"

    # Weekly
    if any(k in q for k in ["week", "weekly", "7 day", "last week", "overnight"]):
        return "weekly"

    # Daily (default)
    return "daily"


def _safe_fetch(fn, *args, error_label: str = "module", **kwargs):
    """
    Safely calls a retrieval function and returns the result or an error dict.
    """
    try:
        return fn(*args, **kwargs)
    except FalconAPIError as e:
        logger.warning(f"[{error_label}] FalconAPIError: {e}")
        return {"error": str(e), "scope_hint": e.scope_hint}
    except Exception as e:
        logger.warning(f"[{error_label}] Unexpected error: {e}")
        return {"error": str(e)}


def run_report_generator(
    user_query: str,
    chat_history: List[Dict[str, str]] = [],
) -> Generator[Dict[str, Any], None, None]:
    """
    Report Generator Agent runner.
    Detects the period, gathers all real data, generates files, streams summary.
    """
    logger.info(f"Running Report Generator for: {user_query!r}")

    # 1. Detect period
    period = _detect_report_period(user_query)
    config = PERIOD_CONFIG[period]
    hours = config["hours"]
    label = config["label"]

    yield {
        "event": "agent_state",
        "data": {
            "agent": "Report Generator",
            "message": f"Generating {label} SOC report from live Falcon data...",
        },
    }

    # ── 2. Detections ──────────────────────────────────────────────────────
    yield {"event": "tool_start", "data": {"name": "query_recent_detections", "params": {"hours": hours}}}
    t0 = time.time()
    from app.tools.crowdstrike.detections import (
        query_recent_detections,
        get_detection_count_by_severity,
    )
    detection_list = _safe_fetch(
        query_recent_detections, hours=hours, max_results=500, error_label="detections"
    )
    severity_counts = _safe_fetch(
        get_detection_count_by_severity, hours=hours, error_label="severity_counts"
    )
    if isinstance(detection_list, dict) and "error" in detection_list:
        detection_list = []
    if isinstance(severity_counts, dict) and "error" in severity_counts:
        severity_counts = {}

    yield {
        "event": "tool_complete",
        "data": {
            "name": "query_recent_detections",
            "status": "success",
            "duration_ms": int((time.time() - t0) * 1000),
            "result": {"count": len(detection_list)},
        },
    }

    # ── 3. Incidents ───────────────────────────────────────────────────────
    yield {"event": "tool_start", "data": {"name": "query_incidents", "params": {"hours": hours}}}
    t0 = time.time()
    from app.tools.crowdstrike.incidents import get_incident_count_by_period
    inc_data = _safe_fetch(get_incident_count_by_period, hours=hours, error_label="incidents")
    if isinstance(inc_data, dict) and "error" in inc_data:
        incident_list = []
        inc_metrics = {"total": 0, "status_breakdown": {}, "avg_score": 0}
    else:
        incident_list = inc_data.get("incidents", [])
        inc_metrics = {
            "total": inc_data.get("total", 0),
            "status_breakdown": inc_data.get("status_breakdown", {}),
            "avg_score": inc_data.get("avg_score", 0),
        }

    yield {
        "event": "tool_complete",
        "data": {
            "name": "query_incidents",
            "status": "success",
            "duration_ms": int((time.time() - t0) * 1000),
            "result": {"count": len(incident_list)},
        },
    }

    # ── 4. Sensor Coverage ─────────────────────────────────────────────────
    yield {"event": "tool_start", "data": {"name": "get_sensor_coverage", "params": {}}}
    t0 = time.time()
    from app.tools.crowdstrike.sensor import get_sensor_coverage, get_version_distribution
    sensor_coverage = _safe_fetch(get_sensor_coverage, error_label="sensor_coverage")
    version_dist = _safe_fetch(get_version_distribution, error_label="version_distribution")

    yield {
        "event": "tool_complete",
        "data": {
            "name": "get_sensor_coverage",
            "status": "success" if "error" not in (sensor_coverage or {}) else "error",
            "duration_ms": int((time.time() - t0) * 1000),
            "result": sensor_coverage,
        },
    }

    # ── 5. Vulnerabilities ─────────────────────────────────────────────────
    yield {"event": "tool_start", "data": {"name": "get_vuln_summary", "params": {}}}
    t0 = time.time()
    from app.tools.crowdstrike.spotlight import (
        get_vuln_summary_by_severity,
        get_kev_vulnerabilities,
        query_vulnerabilities,
    )
    vuln_severity = _safe_fetch(get_vuln_summary_by_severity, error_label="vuln_severity")
    kev_list = _safe_fetch(get_kev_vulnerabilities, max_results=200, error_label="kev")
    vuln_list = _safe_fetch(
        query_vulnerabilities, severity="CRITICAL", status="open", max_results=100,
        error_label="vuln_list"
    )
    if isinstance(vuln_severity, dict) and "error" in vuln_severity:
        vuln_severity = {}
    if isinstance(kev_list, dict) and "error" in kev_list:
        kev_list = []
    if isinstance(vuln_list, dict) and "error" in vuln_list:
        vuln_list = []

    vuln_metrics = {
        "by_severity": vuln_severity,
        "kev_count": len(kev_list),
        "total_open": sum(vuln_severity.values()) if isinstance(vuln_severity, dict) else 0,
    }

    yield {
        "event": "tool_complete",
        "data": {
            "name": "get_vuln_summary",
            "status": "success",
            "duration_ms": int((time.time() - t0) * 1000),
            "result": vuln_metrics,
        },
    }

    # ── 6. KPIs (MTTD / MTTR / Top Threats) ───────────────────────────────
    yield {"event": "tool_start", "data": {"name": "get_kpis", "params": {"hours": hours}}}
    t0 = time.time()
    from app.tools.crowdstrike.metrics import get_mttd, get_mttr, get_top_threats
    mttd = _safe_fetch(get_mttd, hours=hours, error_label="mttd")
    mttr = _safe_fetch(get_mttr, hours=hours, error_label="mttr")
    top_threats = _safe_fetch(get_top_threats, hours=hours, error_label="top_threats")

    yield {
        "event": "tool_complete",
        "data": {
            "name": "get_kpis",
            "status": "success",
            "duration_ms": int((time.time() - t0) * 1000),
            "result": {"mttd": mttd, "mttr": mttr},
        },
    }

    # ── 7. Assemble report data ────────────────────────────────────────────
    yield {
        "event": "agent_state",
        "data": {"agent": "Report Generator", "message": "Compiling report files..."},
    }

    report_data = {
        "title": f"Falcon AI Copilot — {label} SOC Report",
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "scope": "Enterprise Security Endpoints",
        "author": "Falcon AI Copilot (Read-Only)",
        "period_label": label,
        "period_hours": hours,
        "detections": {
            "total": len(detection_list),
            "by_severity": severity_counts,
        },
        "incidents": inc_metrics,
        "sensor_coverage": sensor_coverage if not isinstance(sensor_coverage, dict) or "error" not in sensor_coverage else {},
        "version_distribution": version_dist if not isinstance(version_dist, dict) or "error" not in version_dist else {},
        "vulnerabilities": vuln_metrics,
        "vulnerability_list": vuln_list if isinstance(vuln_list, list) else [],
        "detection_list": detection_list if isinstance(detection_list, list) else [],
        "incident_list": incident_list if isinstance(incident_list, list) else [],
        "mttd": mttd if isinstance(mttd, dict) else {},
        "mttr": mttr if isinstance(mttr, dict) else {},
        "top_threats": top_threats if isinstance(top_threats, dict) else {},
    }

    # ── 8. Generate report files ──────────────────────────────────────────
    static_dir = os.path.join(
        os.path.dirname(os.path.dirname(__file__)), "static", "reports"
    )
    os.makedirs(static_dir, exist_ok=True)

    generated_paths: Dict[str, str] = {}
    try:
        generated_paths = generate_soc_report(
            period=period,
            data=report_data,
            output_dir=static_dir,
        )
    except Exception as e:
        logger.error(f"Report file generation failed: {e}")

    # Build download links
    download_links = []
    for fmt, path in generated_paths.items():
        if path:
            filename = os.path.basename(path)
            download_links.append(f"- [{filename}](/static/reports/{filename})")

    # ── 9. Stream LLM summary ─────────────────────────────────────────────
    yield {
        "event": "agent_state",
        "data": {"agent": "Report Generator", "message": "Generating executive analysis..."},
    }

    download_section = "\n".join(download_links) if download_links else "(Report files not generated)"
    user_prompt = f"""User Request: {user_query}

Report Period: {label}
Lookback Window: {hours} hours

Compiled Metrics:
- Total Detections: {report_data["detections"]["total"]}
- Severity Breakdown: {report_data["detections"]["by_severity"]}
- Total Incidents: {report_data["incidents"]["total"]}
- Incident Avg Score: {report_data["incidents"]["avg_score"]}
- Total Managed Hosts: {report_data["sensor_coverage"].get("total_managed_hosts", "N/A")}
- Sensor Coverage: {report_data["sensor_coverage"].get("coverage_percentage", "N/A")}%
- Offline Sensors (7d): {report_data["sensor_coverage"].get("offline_7d", "N/A")}
- Open Vulnerabilities: {report_data["vulnerabilities"]["total_open"]}
- CISA KEV Count: {report_data["vulnerabilities"]["kev_count"]}
- MTTD: {report_data["mttd"].get("mttd_human", "N/A")}
- MTTR: {report_data["mttr"].get("mttr_human", "N/A")}
- Top Techniques: {[t["name"] for t in report_data["top_threats"].get("top_techniques", [])[:5]]}
- Top Affected Hosts: {[h["name"] for h in report_data["top_threats"].get("top_hosts", [])[:5]]}

Generated Report Files:
{download_section}
"""

    try:
        for token in call_llm_stream(SYSTEM_PROMPT, user_prompt, chat_history):
            yield {"event": "text_chunk", "data": {"text": token}}
    except Exception as e:
        logger.error(f"LLM streaming failed: {e}")
        yield {
            "event": "text_chunk",
            "data": {"text": f"\n[Error generating summary: {e}]\n"},
        }

    yield {
        "event": "complete",
        "data": {"agent": "Report Generator", "status": "success"},
    }
