import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
from app.agents.orchestrator import classify_intent
from app.tools.crowdstrike.playbooks import match_playbook, PLAYBOOKS
from app.tools.crowdstrike.correlation import build_attack_path

def test_orchestrator_routing_keywords():
    # Test that MITRE, correlation and tactic queries route to the SOC analyst
    assert classify_intent("correlate this host and list alerts") == "soc_analyst"
    assert classify_intent("show mitre framework mapping for inc:123") == "soc_analyst"
    assert classify_intent("determine the kill chain tactic for ldt:xyz") == "soc_analyst"

def test_playbook_matching_logic():
    # Test PowerShell execution playbook trigger matching
    sample_powershell_behaviors = [
        {"filename": "powershell.exe", "technique_id": "T1059.001", "technique": "PowerShell"}
    ]
    pb = match_playbook(sample_powershell_behaviors)
    assert pb is not None
    assert pb["name"] == "PowerShell Script Execution Playbook"

    # Test LSASS memory access trigger matching
    sample_lsass_behaviors = [
        {"filename": "rundll32.exe", "technique_id": "T1003.001", "technique": "OS Credential Dumping: LSASS Memory"}
    ]
    pb_lsass = match_playbook(sample_lsass_behaviors)
    assert pb_lsass is not None
    assert pb_lsass["name"] == "LSASS Memory Access Playbook"

    # Test lateral movement trigger matching
    sample_lm_behaviors = [
        {"filename": "wmiprvse.exe", "technique_id": "T1021.002", "technique": "Remote Services"}
    ]
    pb_lm = match_playbook(sample_lm_behaviors)
    assert pb_lm is not None
    assert pb_lm["name"] == "Lateral Movement Playbook"

    # Test no match returned for clean/unmapped behaviors
    clean_behaviors = [
        {"filename": "explorer.exe", "technique_id": "T9999", "technique": "Clean Operation"}
    ]
    assert match_playbook(clean_behaviors) is None

def test_attack_path_generation():
    # Test that build_attack_path constructs a valid attack path chronological timeline
    sample_investigation = {
        "behaviors": [
            {
                "timestamp": "2026-07-08T10:00:00Z",
                "filename": "outlook.exe",
                "tactic": "Initial Access",
                "technique": "Phishing",
                "technique_id": "T1566.001"
            },
            {
                "timestamp": "2026-07-08T10:05:00Z",
                "filename": "powershell.exe",
                "tactic": "Execution",
                "technique": "PowerShell",
                "technique_id": "T1059.001"
            }
        ]
    }
    path = build_attack_path(sample_investigation)
    assert path is not None
    assert "timeline" in path
    assert len(path["timeline"]) == 2
    assert path["timeline"][0]["technique_id"] == "T1566.001"
    assert path["timeline"][1]["technique_id"] == "T1059.001"
