"""
SOC Analyst Agent
==================
Performs live investigations into detections, incidents, hosts, users, and IOCs
using real CrowdStrike Falcon API data. Supports natural-language queries and
routes to the appropriate investigation path automatically.

All operations are strictly read-only.
"""
import logging
import time
import re
from typing import Generator, List, Dict, Any, Optional
from app.agents.llm import call_llm_stream
from app.tools.crowdstrike.client_factory import FalconAPIError

logger = logging.getLogger("soc_analyst")

SYSTEM_PROMPT = """
You are the lead "SOC Analyst" agent (Tier-3 Senior Incident Response Investigator) for the Falcon AI Copilot with 15+ years of CrowdStrike Falcon experience.
Your objective is to investigate threat telemetry, cross-correlate events, validate hypotheses, check exclusions, map incidents to the MITRE ATT&CK framework, analyze business impact, and deliver expert remediation actions.

CORE PILLARS:
1. STRICT ZERO-HALLUCINATION GUARDRAIL: Never guess, fabricate, or invent telemetry, Falcon REST APIs, FalconPy methods, MITRE techniques, or CrowdStrike features. If information cannot be verified from the local knowledge base or live Falcon APIs, state so explicitly.
2. RULE OF CROSS-CORRELATION: "Never Isolated, Always Correlate". You are strictly forbidden from returning telemetry in isolation. Every investigation must correlate: Detection -> Host -> User -> Identity -> IOC -> Threat Actor -> Campaign -> Malware -> MITRE -> Policy -> Incident -> Timeline.
3. HYPOTHESIS-DRIVEN REASONING: Raise threat hypotheses and validate them. Never assume the first answer is correct.

INVESTIGATION LIFE CYCLE & OUTPUT FORMAT:
You MUST structure your report strictly using the following 9-step markdown sections:

# 1. OBSERVE
- Describe the threat hypothesis, the trigger alert details, and initial observations.

# 2. COLLECT EVIDENCE
- List process tree details, command line arguments, user identities, sensor versions, network activity, policy configurations, and vulnerabilities collected from live APIs.

# 3. VALIDATE (SELF-QUERY VERIFICATION)
- Evaluate and list answers to the following diagnostic self-queries in a markdown table with columns "Diagnostic Query | Analysis | Verdict (Yes/No/Unverified)":
  * Is this malware?
  * Is this lateral movement?
  * Is this persistence?
  * Is this privilege escalation?
  * Is this command line suspicious?
  * Is this host compromised?
  * Has this user been seen elsewhere?
  * Has this IOC appeared before?
  * Has this hash appeared on multiple hosts?
  * Could this be ransomware?
  * Could this be a false positive?
  * Could this be an attack chain?

# 4. CORRELATE
- Cross-reference evidence across Host specs, User privileges, Active policies, Falcon Intel (Threat Actors/Malware/Campaigns), and MITRE ATT&CK mappings. Explain matches to standard SOC playbooks (if any).

# 5. DETERMINE SCOPE
- Specify affected assets, endpoints, identity accounts, cloud pods, or subnets.

# 6. DETERMINE ROOT CAUSE
- Map the entry vector (e.g. parent execution binary, initial access spearphishing, vulnerability exploit).

# 7. DETERMINE BUSINESS IMPACT
- Detail operational downtime, data exfiltration risk, confidentiality threat, and compliance impact.

# 8. RECOMMEND NEXT INVESTIGATION STEPS
- Specify next actions, log sweeps, or specific Falcon Console FQL/CQL query commands.

# 9. GENERATE EXECUTIVE SUMMARY
- A high-level, business-impact summary suitable for C-level leadership.

UNIFIED REPORTING STRUCTURE:
Whenever sufficient correlated information exists, structure the report logically with headings for Technical Summary, Executive Summary, Business Impact, MITRE Summary, Attack Narrative, Investigation Timeline, Recommended Actions, and Next Investigation Steps inside the sections above. Success is measured by investigation quality, accuracy, and technical recommendations—not conversational tone.
"""


def _safe_call(fn, *args, label: str = "", **kwargs):
    """Calls a function and returns (result, error_msg) tuple."""
    try:
        return fn(*args, **kwargs), None
    except FalconAPIError as e:
        msg = f"[{label}] API Error {e.status_code}: {e.errors}"
        if e.scope_hint:
            msg += f" | Required scope: {e.scope_hint}"
        logger.warning(msg)
        return None, msg
    except ValueError as e:
        logger.warning(f"[{label}] Validation error: {e}")
        return None, str(e)
    except Exception as e:
        logger.warning(f"[{label}] Unexpected error: {e}")
        return None, str(e)


def _extract_token(query: str, prefixes: List[str]) -> Optional[str]:
    """
    Extracts a token from the query matching one of the given prefix patterns.
    Used to extract incident IDs, detection IDs, hostnames, etc.
    """
    words = query.split()
    for word in words:
        for prefix in prefixes:
            if word.lower().startswith(prefix.lower()):
                return word
    return None


def _extract_hours_from_query(query: str) -> int:
    """
    Parses natural-language time expressions from a query string.
    Returns the lookback window in hours.
    """
    q = query.lower()

    # Named periods
    if "overnight" in q:
        return 12
    if "last 30 day" in q or "30 day" in q or "month" in q:
        return 720
    if "last 7 day" in q or "7 day" in q or "week" in q:
        return 168
    if "last 3 day" in q or "3 day" in q or "72 hour" in q:
        return 72

    # Extract number before "hour"
    match = re.search(r"(\d+)\s*hour", q)
    if match:
        return min(int(match.group(1)), 8760)

    # Default: 24 hours
    return 24


def run_soc_analyst(
    user_query: str,
    chat_history: List[Dict[str, str]] = [],
) -> Generator[Dict[str, Any], None, None]:
    """
    SOC Analyst Agent runner. Routes the query to the appropriate investigation
    path and streams results.
    """
    logger.info(f"SOC Analyst processing: {user_query!r}")
    q = user_query.lower()
    hours = _extract_hours_from_query(user_query)

    # ── Path 1: Incident Investigation ────────────────────────────────────
    if "incident" in q or "inc:" in q:
        yield {"event": "agent_state", "data": {"agent": "SOC Analyst", "message": "Investigating incident..."}}

        inc_id = _extract_token(user_query, ["inc:", "INC-"])

        if inc_id:
            yield {"event": "tool_start", "data": {"name": "get_incident_details", "params": {"incident_id": inc_id}}}
            t0 = time.time()
            from app.tools.crowdstrike.incidents import get_incident_details
            incident, err = _safe_call(get_incident_details, inc_id, label="get_incident_details")
            yield {
                "event": "tool_complete",
                "data": {
                    "name": "get_incident_details",
                    "status": "success" if incident else "error",
                    "duration_ms": int((time.time() - t0) * 1000),
                    "result": {"found": incident is not None, "error": err},
                },
            }

            if incident:
                from app.tools.crowdstrike.correlation import build_unified_incident_investigation, build_attack_path
                from app.tools.crowdstrike.hosts import get_host_login_history
                from app.tools.crowdstrike.spotlight import query_vulnerabilities
                from app.tools.crowdstrike.identity import query_identity_alerts
                from app.tools.crowdstrike.playbooks import match_playbook

                yield {"event": "agent_state", "data": {"agent": "SOC Analyst", "message": "Correlating incident telemetry (hosts, users, timeline, MITRE)..."}}
                investigation, _ = _safe_call(build_unified_incident_investigation, incident, label="incident_correlation")
                attack_path = build_attack_path(investigation) if investigation else {}

                host_vulns = {}
                host_logins = {}
                hosts_involved = investigation.get("hosts", []) if investigation else []
                for h in hosts_involved[:3]:
                    h_id = h.get("device_id")
                    if h_id:
                        h_name = h.get("hostname", h_id)
                        v, _ = _safe_call(query_vulnerabilities, aid=h_id, max_results=10, label=f"vulns_{h_name}")
                        host_vulns[h_name] = v or []
                        log, _ = _safe_call(get_host_login_history, host_id=h_id, max_results=10, label=f"logins_{h_name}")
                        host_logins[h_name] = log or []

                id_alerts, _ = _safe_call(query_identity_alerts, hours=hours, label="identity_alerts")
                matched_pb = match_playbook(investigation.get("behaviors", [])) if investigation else None

                prompt_context = (
                    f"INCIDENT DETAILS:\n{incident}\n\n"
                    f"CORRELATED INCIDENT INVESTIGATION:\n{investigation}\n\n"
                    f"MITRE ATT&CK ATTACK PATH:\n{attack_path}\n\n"
                    f"IDENTITY ALERTS:\n{id_alerts}\n\n"
                    f"VULNERABILITIES BY HOST:\n{host_vulns}\n\n"
                    f"LOGINS BY HOST:\n{host_logins}\n\n"
                    f"AUTOMATED PLAYBOOK MATCHED:\n{matched_pb}\n\n"
                )
            else:
                prompt_context = f"Incident '{inc_id}' could not be retrieved. Error: {err}"
        else:
            yield {"event": "tool_start", "data": {"name": "query_incidents", "params": {"hours": hours}}}
            t0 = time.time()
            from app.tools.crowdstrike.incidents import query_incidents
            incidents, err = _safe_call(query_incidents, hours=hours, max_results=20, label="query_incidents")
            yield {
                "event": "tool_complete",
                "data": {
                    "name": "query_incidents",
                    "status": "success" if incidents is not None else "error",
                    "duration_ms": int((time.time() - t0) * 1000),
                    "result": {"count": len(incidents) if incidents else 0},
                },
            }
            prompt_context = f"Recent Incidents (last {hours}h):\n{incidents}\nError: {err}"

    # ── Path 2: Host / Endpoint Investigation ──────────────────────────────
    elif any(k in q for k in ["host", "device", "endpoint", "machine", "workstation", "server", "laptop"]):
        yield {"event": "agent_state", "data": {"agent": "SOC Analyst", "message": "Locating endpoint..."}}

        is_list_request = any(k in q for k in ["list", "all", "show me hosts", "show hosts", "show devices"])
        hostname = None
        patterns = [
            r'\b([A-Za-z]{2,6}-?[A-Za-z]?[0-9]{2,6})\b',
            r'\b([A-Za-z]+\d{2,}[A-Za-z]*)\b',
        ]
        for pattern in patterns:
            match = re.search(pattern, user_query)
            if match:
                hostname = match.group(1).upper()
                break

        if not hostname and not is_list_request:
            words = [w for w in user_query.split() if len(w) > 2 and w.isalnum()]
            generic_words = {"HOST", "HOSTS", "DEVICE", "DEVICES", "ENDPOINT", "ENDPOINTS", "MACHINE", "MACHINES"}
            if words and words[-1].upper() not in generic_words:
                hostname = words[-1].upper()

        if hostname:
            yield {"event": "tool_start", "data": {"name": "search_host", "params": {"hostname": hostname}}}
            t0 = time.time()
            from app.tools.crowdstrike.hosts import search_host
            host_list, err = _safe_call(search_host, hostname, label="search_host")
            yield {
                "event": "tool_complete",
                "data": {
                    "name": "search_host",
                    "status": "success" if host_list is not None else "error",
                    "duration_ms": int((time.time() - t0) * 1000),
                    "result": {"hosts_found": len(host_list) if host_list else 0},
                },
            }

            if host_list:
                host = host_list[0]
                host_id = host.get("device_id", "")
                host_name = host.get("hostname", hostname)

                from app.tools.crowdstrike.hosts import get_host_detections, get_host_login_history
                from app.tools.crowdstrike.discover import query_applications
                from app.tools.crowdstrike.spotlight import query_vulnerabilities
                from app.tools.crowdstrike.policies import list_prevention_policies
                from app.tools.crowdstrike.playbooks import match_playbook

                yield {"event": "agent_state", "data": {"agent": "SOC Analyst", "message": f"Executing Host Triage Pipeline (apps, logins, detections, vulns, policies) for {host_name}..."}}
                apps, _ = _safe_call(query_applications, hostname=host_name, max_results=30, label="host_apps")
                logins, _ = _safe_call(get_host_login_history, host_id=host_id, max_results=15, label="host_logins")
                detections, _ = _safe_call(get_host_detections, host_id=host_id, label="host_detections")
                vulns, _ = _safe_call(query_vulnerabilities, aid=host_id, status="open", max_results=20, label="host_vulns")
                policies, _ = _safe_call(list_prevention_policies, enabled_only=True, max_results=20, label="prevention_policies")

                behaviors = []
                for det in (detections or []):
                    behaviors.extend(det.get("behaviors", []))
                matched_pb = match_playbook(behaviors)

                prompt_context = (
                    f"HOST DETAILS:\n{host}\n\n"
                    f"INSTALLED APPLICATIONS:\n{apps}\n\n"
                    f"LOGGED USERS & LOGINS:\n{logins}\n\n"
                    f"RECENT DETECTIONS ON HOST:\n{detections}\n\n"
                    f"OPEN VULNERABILITIES ON HOST:\n{vulns}\n\n"
                    f"ACTIVE PREVENTION POLICIES:\n{policies}\n\n"
                    f"AUTOMATED PLAYBOOK MATCHED:\n{matched_pb}\n\n"
                )
            else:
                prompt_context = f"No host found matching '{hostname}'. Error: {err}"
        else:
            yield {"event": "tool_start", "data": {"name": "list_all_hosts", "params": {"max_results": 1000}}}
            t0 = time.time()
            from app.tools.crowdstrike.hosts import list_all_hosts
            hosts, err = _safe_call(list_all_hosts, max_results=1000, label="list_all_hosts")
            yield {
                "event": "tool_complete",
                "data": {
                    "name": "list_all_hosts",
                    "status": "success" if hosts is not None else "error",
                    "duration_ms": int((time.time() - t0) * 1000),
                    "result": {"hosts_found": len(hosts) if hosts else 0},
                },
            }
            if hosts:
                concise_hosts = []
                for h in hosts:
                    concise_hosts.append({
                        "hostname": h.get("hostname", "NA") or "NA",
                        "os_version": h.get("os_version", "NA") or "NA",
                        "local_ip": h.get("local_ip", "NA") or "NA",
                        "agent_version": h.get("agent_version", "NA") or "NA",
                        "last_seen": h.get("last_seen", "NA") or "NA",
                        "status": h.get("status", "NA") or "NA"
                    })
                prompt_context = f"List of Hosts ({len(concise_hosts)} found):\n{concise_hosts}"
            else:
                prompt_context = f"No hosts found. Error: {err}"

    # ── Path 3: IOC Pivot ─────────────────────────────────────────────────
    elif any(k in q for k in ["ioc", "indicator", "pivot", "hash", "sha256", "domain", "ip"]):
        yield {"event": "agent_state", "data": {"agent": "SOC Analyst", "message": "Performing IOC pivot..."}}

        ioc_type, ioc_value = _detect_ioc_from_query(user_query)

        if ioc_value:
            yield {"event": "tool_start", "data": {"name": "correlate_ioc", "params": {"type": ioc_type, "value": ioc_value}}}
            t0 = time.time()
            from app.tools.crowdstrike.correlation import correlate_ioc
            from app.tools.crowdstrike.intel import lookup_ioc
            from app.tools.crowdstrike.playbooks import match_playbook

            pivot_result, err = _safe_call(correlate_ioc, ioc_type, ioc_value, label="correlate_ioc")
            yield {
                "event": "tool_complete",
                "data": {
                    "name": "correlate_ioc",
                    "status": "success" if pivot_result else "error",
                    "duration_ms": int((time.time() - t0) * 1000),
                    "result": {
                        "related_detections": len(pivot_result.get("related_detections", [])) if pivot_result else 0,
                        "affected_hosts": pivot_result.get("affected_hosts", []) if pivot_result else [],
                    },
                },
            }

            intel_data, _ = _safe_call(lookup_ioc, ioc_type, ioc_value, label="lookup_ioc")

            prompt_context = (
                f"IOC PIVOT RESULTS:\n{pivot_result}\n\n"
                f"FALCON THREAT INTELLIGENCE ANALYSIS:\n{intel_data}\n\n"
            )
        else:
            prompt_context = "Could not identify a specific IOC value in your query. Please provide a hash, IP, or domain."

    # ── Path 4: User Activity Investigation ───────────────────────────────
    elif any(k in q for k in ["user", "account", "identity", "login", "logon", "credential"]):
        yield {"event": "agent_state", "data": {"agent": "SOC Analyst", "message": "Investigating user activity..."}}

        email_match = re.search(r"[\w.+-]+@[\w-]+\.[a-z]{2,}", user_query)

        if email_match:
            email = email_match.group(0)
            yield {"event": "tool_start", "data": {"name": "search_user_by_email", "params": {"email": email}}}
            t0 = time.time()
            from app.tools.crowdstrike.users import search_user_by_email, get_user_roles
            user, err = _safe_call(search_user_by_email, email, label="search_user_by_email")
            roles = None
            if user and user.get("uuid"):
                roles, _ = _safe_call(get_user_roles, user["uuid"], label="get_user_roles")
            yield {
                "event": "tool_complete",
                "data": {
                    "name": "search_user_by_email",
                    "status": "success" if user else "error",
                    "duration_ms": int((time.time() - t0) * 1000),
                    "result": {"found": user is not None},
                },
            }
            prompt_context = f"User Profile:\n{user}\nRoles:\n{roles}"
        else:
            yield {"event": "tool_start", "data": {"name": "query_identity_alerts", "params": {"hours": hours}}}
            t0 = time.time()
            from app.tools.crowdstrike.identity import query_identity_alerts
            id_alerts, err = _safe_call(query_identity_alerts, hours=hours, label="identity_alerts")
            yield {
                "event": "tool_complete",
                "data": {
                    "name": "query_identity_alerts",
                    "status": "success" if id_alerts is not None else "error",
                    "duration_ms": int((time.time() - t0) * 1000),
                    "result": {"alerts_found": len(id_alerts) if id_alerts else 0},
                },
            }
            prompt_context = f"Identity Alerts (last {hours}h):\n{id_alerts}\nError: {err}"

    # ── Path 5: Detection / Alert Investigation (default) ─────────────────
    else:
        yield {"event": "agent_state", "data": {"agent": "SOC Analyst", "message": "Querying detections..."}}

        det_id = _extract_token(user_query, ["ldt:"])
        severity = None
        for sev in ["critical", "high", "medium", "low"]:
            if sev in q:
                severity = sev.upper()
                break

        if det_id:
            yield {"event": "tool_start", "data": {"name": "get_detection_details", "params": {"id": det_id}}}
            t0 = time.time()
            from app.tools.crowdstrike.detections import get_detection_details
            detection, err = _safe_call(get_detection_details, det_id, label="get_detection_details")
            yield {
                "event": "tool_complete",
                "data": {
                    "name": "get_detection_details",
                    "status": "success" if detection else "error",
                    "duration_ms": int((time.time() - t0) * 1000),
                    "result": {"found": detection is not None},
                },
            }

            if detection:
                from app.tools.crowdstrike.correlation import build_unified_detection_investigation, build_attack_path
                from app.tools.crowdstrike.spotlight import query_vulnerabilities
                from app.tools.crowdstrike.playbooks import match_playbook
                from app.tools.crowdstrike.detections import query_recent_detections

                yield {"event": "agent_state", "data": {"agent": "SOC Analyst", "message": "Correlating behaviors, timeline, network activity, process tree & MITRE..."}}
                investigation, _ = _safe_call(build_unified_detection_investigation, detection, label="detection_correlation")
                attack_path = build_attack_path(investigation) if investigation else {}

                host_id = detection.get("device", {}).get("device_id")
                host_vulns = []
                related_alerts = []
                if host_id:
                    host_vulns, _ = _safe_call(query_vulnerabilities, aid=host_id, status="open", max_results=10, label="host_vulns")
                    related_alerts, _ = _safe_call(query_recent_detections, hostname=detection.get("device", {}).get("hostname"), max_results=10, label="related_host_alerts")

                matched_pb = match_playbook(detection.get("behaviors", []))

                prompt_context = (
                    f"DETECTION DETAILS:\n{detection}\n\n"
                    f"CORRELATED DETECTION INVESTIGATION:\n{investigation}\n\n"
                    f"MITRE ATT&CK ATTACK PATH:\n{attack_path}\n\n"
                    f"HOST VULNERABILITIES:\n{host_vulns}\n\n"
                    f"RELATED DETECTIONS ON SAME ENDPOINT:\n{related_alerts}\n\n"
                    f"AUTOMATED PLAYBOOK MATCHED:\n{matched_pb}\n\n"
                )
            else:
                prompt_context = f"Detection '{det_id}' not found. Error: {err}"
        else:
            yield {"event": "tool_start", "data": {"name": "query_recent_detections", "params": {"hours": hours, "severity": severity}}}
            t0 = time.time()
            from app.tools.crowdstrike.detections import query_recent_detections
            from app.tools.crowdstrike.playbooks import match_playbook
            from app.tools.crowdstrike.correlation import build_attack_path

            detections, err = _safe_call(
                query_recent_detections, hours=hours, severity=severity, max_results=50,
                label="query_recent_detections"
            )
            yield {
                "event": "tool_complete",
                "data": {
                    "name": "query_recent_detections",
                    "status": "success" if detections is not None else "error",
                    "duration_ms": int((time.time() - t0) * 1000),
                    "result": {"alerts_found": len(detections) if detections else 0},
                },
            }

            if detections:
                yield {"event": "agent_state", "data": {"agent": "SOC Analyst", "message": "Correlating and mapping recent alert indicators..."}}
                synthetic_investigation = {"behaviors": []}
                for det in detections:
                    synthetic_investigation["behaviors"].extend(det.get("behaviors", []))
                
                attack_path = build_attack_path(synthetic_investigation)
                matched_pb = match_playbook(synthetic_investigation["behaviors"])

                prompt_context = (
                    f"RECENT DETECTIONS (last {hours}h, severity={severity or 'all'}):\n"
                    f"{detections}\n\n"
                    f"SYNTHESIZED MITRE ATT&CK ATTACK PATH:\n{attack_path}\n\n"
                    f"AUTOMATED PLAYBOOK MATCHED:\n{matched_pb}\n\n"
                )
            else:
                prompt_context = f"No recent detections found to correlate. Error: {err}"

    # ── Stream LLM Response ───────────────────────────────────────────────
    yield {"event": "agent_state", "data": {"agent": "SOC Analyst", "message": "Generating investigation report..."}}

    try:
        user_prompt = (
            f"User Request: {user_query}\n\n"
            f"Live CrowdStrike Falcon API Data:\n{prompt_context}"
        )
        for token in call_llm_stream(SYSTEM_PROMPT, user_prompt, chat_history):
            yield {"event": "text_chunk", "data": {"text": token}}
    except Exception as e:
        logger.error(f"LLM streaming error: {e}")
        yield {"event": "text_chunk", "data": {"text": f"\n[Error generating report: {e}]\n"}}

    yield {"event": "complete", "data": {"agent": "SOC Analyst", "status": "success"}}


def _detect_ioc_from_query(query: str):
    """
    Attempts to identify an IOC type and value from a natural-language query.
    Returns (type, value) tuple or (None, None) if not found.
    """
    # SHA256 — 64 hex chars
    match = re.search(r'\b[a-fA-F0-9]{64}\b', query)
    if match:
        return "sha256", match.group(0)

    # MD5 — 32 hex chars
    match = re.search(r'\b[a-fA-F0-9]{32}\b', query)
    if match:
        return "md5", match.group(0)

    # IPv4
    match = re.search(
        r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b',
        query
    )
    if match:
        return "ipv4", match.group(0)

    # Domain
    match = re.search(r'\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|ru|cn|gov|edu|co)\b', query)
    if match:
        return "domain", match.group(0)

    # URL
    match = re.search(r'https?://[^\s]+', query)
    if match:
        return "url", match.group(0)

    return "unknown", None
