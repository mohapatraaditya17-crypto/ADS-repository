import logging
from typing import List, Dict, Any

logger = logging.getLogger("timeline_builder")

def build_process_tree(behaviors: List[Dict[str, Any]]) -> str:
    """
    Reconstructs a parent -> child process tree visualizer in plain text.
    """
    if not behaviors:
        return "No process behaviors logged."
        
    tree_lines = []
    tree_lines.append("PROCESS TREE:")
    tree_lines.append("──────────────────────────────────────────────")
    
    # Simple formatting of process relationships
    for idx, b in enumerate(behaviors):
        cmd = b.get("cmdline", "unknown")
        proc_name = b.get("filename", "unknown")
        tactic = b.get("tactic", "unknown")
        
        if idx == 0:
            tree_lines.append(f"  [Parent] {proc_name} (Command: {cmd})")
        elif idx == 1:
            tree_lines.append(f"    └── [Suspicious Child] {proc_name} (Command: {cmd})  ← tactic: {tactic}")
        else:
            tree_lines.append(f"         └── [Target Action] {proc_name} (Command: {cmd})")
            
    return "\n".join(tree_lines)

def build_incident_timeline(incident: Dict[str, Any]) -> str:
    """
    Generates a text-based chronological attack timeline from incident metadata.
    """
    if not incident:
        return "No incident metadata available."
        
    timeline = []
    timeline.append(f"ATTACK TIMELINE — {incident.get('incident_id', 'INCIDENT')}")
    timeline.append("══════════════════════════════════════════════")
    
    hosts = ", ".join(incident.get("hosts", []))
    users = ", ".join(incident.get("users", []))
    timeline.append(f"Scope: {incident.get('detections_count', 0)} alerts across {len(incident.get('hosts', []))} hosts ({hosts}) and users ({users}).")
    timeline.append("")
    
    timestamp = incident.get("created_timestamp", "2026-07-07T13:00:00Z")
    
    # Simulate step-by-step chronology mapping
    timeline.append(f"  {timestamp[:16]} - [Initial Compromise] Host system alert triggered.")
    timeline.append(f"  {timestamp[:16]} - [Execution] Threat indicators detected running credentials scripts.")
    timeline.append(f"  {timestamp[:16]} - [Lateral Movement] Account credentials used for SMB share authentication.")
    timeline.append(f"  {timestamp[:16]} - [Persistence] System startup task scheduled.")
    
    return "\n".join(timeline)
