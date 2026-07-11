"""
CrowdStrike Falcon Process Retrieval Module
===========================================
Extracts and builds process execution data from CrowdStrike Falcon detection behaviors.

Note: There is no standalone ProcessesAPI in standard FalconPy without specific
FDR/Flight Control services. This module instead extracts process tree logic
from alert/behavior telemetry.
"""
import logging
from typing import List, Dict, Any

logger = logging.getLogger("crowdstrike_processes")

def extract_process_ids_from_behaviors(
    behaviors: List[Dict[str, Any]],
) -> List[str]:
    """
    Extracts process IDs from detection behavior objects.
    """
    pids: List[str] = []
    for b in behaviors:
        for field in ("triggering_process_graph_id", "parent_process_graph_id"):
            val = b.get(field)
            if val and val not in pids:
                pids.append(val)
    return pids

def build_process_tree_from_behaviors(
    behaviors: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Constructs a simplified process tree from behavior data without
    requiring additional API calls. Uses inline process fields from behaviors.

    Args:
        behaviors: List of behavior dicts from detection data

    Returns:
        List of process node dicts ordered from parent to child
    """
    nodes: List[Dict[str, Any]] = []
    seen_pids: set = set()

    for b in behaviors:
        parent_pid = b.get("parent_process_id")
        parent_img = b.get("parent_image_file_name") or b.get("parent_details", {}).get("filename")
        child_pid = b.get("process_id")
        child_img = b.get("filename")
        cmdline = b.get("cmdline") or b.get("command_line")
        user = b.get("user_name")

        if parent_img and parent_pid and parent_pid not in seen_pids:
            seen_pids.add(parent_pid)
            nodes.append({
                "pid": parent_pid,
                "image": parent_img,
                "role": "parent",
                "cmdline": b.get("parent_cmdline"),
                "user": user,
            })

        if child_img and child_pid and child_pid not in seen_pids:
            seen_pids.add(child_pid)
            nodes.append({
                "pid": child_pid,
                "image": child_img,
                "role": "child",
                "cmdline": cmdline,
                "user": user,
                "tactic": b.get("tactic"),
                "technique": b.get("technique"),
                "technique_id": b.get("technique_id"),
            })

    return nodes
