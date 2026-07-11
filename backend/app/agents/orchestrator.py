"""
Falcon AI Copilot Orchestrator
================================
Analyzes user intent and routes queries to the appropriate specialist agent.
Supports natural-language investigation requests, SOC reports, threat hunting,
policy analysis, audit, and general knowledge questions.
"""
import logging
import re
from typing import Generator, List, Dict, Any
from app.agents.knowledge_expert import run_knowledge_expert
from app.agents.threat_hunter import run_threat_hunter
from app.agents.falcon_engineer import run_falcon_engineer
from app.agents.soc_analyst import run_soc_analyst
from app.agents.policy_analyst import run_policy_analyst
from app.agents.report_generator import run_report_generator
from app.agents.audit_analyst import run_audit_analyst

logger = logging.getLogger("orchestrator")


def classify_intent(query: str) -> str:
    """
    Classifies the user prompt intent into one of the specialized agents:

    - 'threat_hunter'   : FQL/CQL/SPL query generation, hunting hypotheses
    - 'falcon_engineer' : Script/code generation (Python, PowerShell, FalconPy)
    - 'soc_analyst'     : Live investigations — detections, incidents, hosts, IOCs, users
    - 'policy_analyst'  : Prevention, firewall, device control, exclusion policy review
    - 'report_generator': SOC reports — daily, weekly, monthly, quarterly, annual
    - 'audit_analyst'   : OAuth2 clients, RBAC, integrations, compliance audit
    - 'knowledge_expert': Falcon documentation, general questions (default)

    Args:
        query: User's natural-language query

    Returns:
        Intent label string
    """
    q = query.lower()

    # ── Code / Script Generation ──────────────────────────────────────────
    script_keywords = [
        "script", "python", "powershell", "code", "falconpy",
        "sdk", "write a program", "rest api", "api client",
        "snippet", "function", "module", "example code",
    ]
    if any(k in q for k in script_keywords):
        return "falcon_engineer"

    # ── Query / Threat Hunting ────────────────────────────────────────────
    query_keywords = [
        "fql query", "cql query", "splunk spl", "spl query", "logscale cql",
        "hunting query", "hunt for", "write a query", "generate a query",
        "sigma rule", "yara rule", "suricata", "kql query",
        "threat hunt", "hunt powershell", "hunt lateral",
    ]
    if any(k in q for k in query_keywords):
        return "threat_hunter"

    # ── SOC Reports (must check BEFORE policy/audit keywords) ────────────
    report_keywords = [
        "daily report", "weekly report", "monthly report",
        "quarterly report", "annual report", "yearly report",
        "soc report", "executive report", "executive summary report",
        "generate report", "compile report", "export report",
        "security report", "threat report",
        "what happened overnight", "overnight summary",
        "q1 report", "q2 report", "q3 report", "q4 report",
        "summarize the week", "summarize the month",
    ]
    if any(k in q for k in report_keywords):
        return "report_generator"

    # ── Policy Analysis ───────────────────────────────────────────────────
    policy_keywords = [
        "policy", "policies", "prevention setting", "firewall rule",
        "compare policy", "gap analysis", "uninstall protection",
        "exclusion list", "ml exclusion", "ioa exclusion",
        "device control", "sensor update policy", "host group",
        "ioa rule", "response policy",
    ]
    if any(k in q for k in policy_keywords):
        return "policy_analyst"

    # ── Compliance / Audit ────────────────────────────────────────────────
    audit_keywords = [
        "audit", "oauth", "api client", "scope", "rbac",
        "integration health", "health check", "compliance",
        "permission", "user role", "api key",
    ]
    if any(k in q for k in audit_keywords):
        return "audit_analyst"

    # ── Live SOC Investigations ───────────────────────────────────────────
    soc_keywords = [
        # Incident keywords
        "incident", "inc:", "investigate incident",
        # Detection keywords
        "detect", "alert", "ldt:", "recent detection", "recent alert",
        "what happened", "triage", "investigate detection",
        # Host keywords
        "host", "device", "endpoint", "machine", "workstation",
        "server", "laptop", "investigate host", "show host",
        # IOC pivot
        "ioc", "indicator", "pivot on", "hash", "sha256", "md5",
        "ip address", "domain name", "malicious",
        # User/Identity
        "user activity", "login history", "logon", "credential",
        "identity alert", "compromised account", "pass-the-hash",
        "kerberoasting", "lateral movement",
        # Vulnerability
        "vulnerability", "cve", "spotlight", "patch", "exploit", "kev",
        # Sensor
        "offline sensor", "sensor coverage", "rfm", "reduced function",
        "sensor version", "sensor health",
        # MITRE ATT&CK & Correlation Engine keywords
        "mitre", "attack framework", "correlate", "correlation", "kill chain", "tactic", "technique",
        # Time-bounded queries
        "last 24 hours", "last hour", "this morning", "today",
        "last 30 days", "last week",
    ]
    if any(k in q for k in soc_keywords):
        return "soc_analyst"

    # ── Default: General Knowledge ────────────────────────────────────────
    return "knowledge_expert"


def route_and_run(
    user_query: str,
    chat_history: List[Dict[str, str]] = [],
) -> Generator[Dict[str, Any], None, None]:
    """
    Orchestration entry point. Analyzes user intent, routes to the correct
    specialist agent, and yields SSE events from that agent's stream.

    Args:
        user_query: The user's natural-language query
        chat_history: Prior conversation messages for context

    Yields:
        SSE event dicts from the selected agent stream
    """
    intent = classify_intent(user_query)
    logger.info(f"Orchestrator routing to '{intent}' agent for query: {user_query!r}")

    # Emit routing event so the frontend can show which agent is active
    yield {
        "event": "agent_state",
        "data": {
            "agent": "Orchestrator",
            "message": f"Routing to {intent.replace('_', ' ').title()} agent...",
            "selected_agent": intent,
        },
    }

    if intent == "threat_hunter":
        yield from run_threat_hunter(user_query, chat_history)
    elif intent == "falcon_engineer":
        yield from run_falcon_engineer(user_query, chat_history)
    elif intent == "soc_analyst":
        yield from run_soc_analyst(user_query, chat_history)
    elif intent == "policy_analyst":
        yield from run_policy_analyst(user_query, chat_history)
    elif intent == "report_generator":
        yield from run_report_generator(user_query, chat_history)
    elif intent == "audit_analyst":
        yield from run_audit_analyst(user_query, chat_history)
    else:
        yield from run_knowledge_expert(user_query, chat_history)
