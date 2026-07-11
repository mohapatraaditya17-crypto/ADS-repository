"""
Investigation Playbook Engine for Falcon AI Copilot
===================================================
Defines structured incident playbooks containing triggers, API collections,
decision points, false-positive metrics, escalation rules, and reports.
"""
from typing import List, Dict, Any, Optional

PLAYBOOKS: Dict[str, Dict[str, Any]] = {
    "powershell_execution": {
        "name": "PowerShell Script Execution Playbook",
        "trigger_conditions": {
            "processes": ["powershell.exe", "pwsh.exe"],
            "techniques": ["T1059.001"]
        },
        "evidence_to_collect": [
            "Encoded command strings", "Execution policy bypass arguments",
            "Network sockets established by powershell.exe", "Active directory group changes by script"
        ],
        "api_calls": [
            "get_detection_details", "get_host_details", "get_network_events_for_detection"
        ],
        "correlation_logic": "Analyze if powershell.exe is spawned by an unusual parent process (e.g. w3wp.exe, outlook.exe, sqlservr.exe). Trace any network outbound events mapped to the process execution lifetime.",
        "decision_points": [
            "Is the script running with administrative credentials?",
            "Does the script contain obfuscated command lines or base64 structures?"
        ],
        "escalation_criteria": "Active directory command execution (e.g. net.exe, dsquery.exe) by script running on domain controllers or high-value business assets.",
        "false_positive_checks": [
            "Verify if the script matches scheduled internal administrative deployment tasks",
            "Check if the command hash belongs to standard monitoring tools (e.g. Datadog, SCCM)"
        ],
        "mitre_mapping": {
            "tactic": "Execution",
            "technique_id": "T1059.001",
            "technique": "Command and Scripting Interpreter: PowerShell"
        },
        "reporting_template": "TECHNICAL SUMMARY: [Brief script analysis]\nROOT CAUSE: [Parent process that executed script]\nBUSINESS IMPACT: [Impacted endpoints/accounts]\nRECOMMENDED ACTIONS: [Remediation instructions]"
    },
    "ransomware_detection": {
        "name": "Ransomware Detection Playbook",
        "trigger_conditions": {
            "techniques": ["T1486"],
            "behaviors": ["ransomware", "encrypt", "shadowcopy"]
        },
        "evidence_to_collect": [
            "Volume Shadow Copy deletion commands", "High-frequency file modifications",
            "Known ransomware extensions appended", "Associated encryption note files"
        ],
        "api_calls": [
            "get_detection_details", "get_host_details", "query_recent_detections"
        ],
        "correlation_logic": "Trace process tree to identify target file traversal and check if volume shadow copy deletion occurred via vssadmin.exe or wmic.exe.",
        "decision_points": [
            "Has encryption begun on user files or host filesystems?",
            "Are backup catalogs or system recovery parameters disabled?"
        ],
        "escalation_criteria": "Ransomware IOA matching active volume shadow deletion or encryption patterns on critical file shares or application database hosts.",
        "false_positive_checks": [
            "Verify if corporate file backup agents or bulk archiving tools are active on host",
            "Check if the user is running compression tools manually"
        ],
        "mitre_mapping": {
            "tactic": "Impact",
            "technique_id": "T1486",
            "technique": "Data Encrypted for Impact"
        },
        "reporting_template": "TECHNICAL SUMMARY: [Ransomware binary analysis]\nROOT CAUSE: [Initial vector / execution agent]\nBUSINESS IMPACT: [Encryption scope and share drives affected]\nRECOMMENDED ACTIONS: [Isolate host immediately and suspend compromised credentials]"
    },
    "lsass_access": {
        "name": "LSASS Memory Access Playbook",
        "trigger_conditions": {
            "techniques": ["T1003.001"],
            "behaviors": ["lsass", "mini-dump", "rundll32_lsass"]
        },
        "evidence_to_collect": [
            "Processes targeting lsass.exe process handle", "Process memory dump parameters",
            "Credentials harvested or loaded into process memory", "Outbound logins from host"
        ],
        "api_calls": [
            "get_detection_details", "get_host_details", "get_host_login_history"
        ],
        "correlation_logic": "Correlate LSASS memory access events with suspicious credential helper loading (e.g. SSPs) or dumping tools like Mimikatz/Procdump.",
        "decision_points": [
            "Was lsass.exe memory dumped to a file on disk?",
            "Did the dumping process run with NT AUTHORITY\\SYSTEM privileges?"
        ],
        "escalation_criteria": "LSASS dumping event on Active Directory Domain Controllers or high-level privilege administration consoles.",
        "false_positive_checks": [
            "Check if specialized security agents (EDR, antivirus, vulnerability scanners) are auditing LSASS handles",
            "Confirm if custom developer diagnostic memory dumps are running"
        ],
        "mitre_mapping": {
            "tactic": "Credential Access",
            "technique_id": "T1003.001",
            "technique": "OS Credential Dumping: LSASS Memory"
        },
        "reporting_template": "TECHNICAL SUMMARY: [LSASS access analysis]\nROOT CAUSE: [Dumping tool / process trigger]\nBUSINESS IMPACT: [Credential theft compromise threat level]\nRECOMMENDED ACTIONS: [Reset compromised account passwords, run security audits]"
    },
    "credential_dumping": {
        "name": "Credential Dumping Playbook",
        "trigger_conditions": {
            "techniques": ["T1003"],
            "behaviors": ["sam_dump", "ntds_dump", "mimikatz"]
        },
        "evidence_to_collect": [
            "SAM/SECURITY registry hive export commands", "Mimikatz command execution arguments",
            "NTDS.dit file copying or access logs", "Security account database extractions"
        ],
        "api_calls": [
            "get_detection_details", "get_host_details", "get_host_login_history"
        ],
        "correlation_logic": "Look for system command strings reading registry hives directly (e.g. reg save HKLM\\SAM) or copying NTDS database via volume shadow copy client tools.",
        "decision_points": [
            "Was the SAM hive or NTDS file copied to a local staging folder?",
            "Are execution logs matching mimikatz or similar harvesting binaries present?"
        ],
        "escalation_criteria": "Exporting of Active Directory NTDS database from domain controllers.",
        "false_positive_checks": [
            "Verify if authorized IT administrators are extracting diagnostic details",
            "Determine if regular system backup tools are reading registry/NTDS structures"
        ],
        "mitre_mapping": {
            "tactic": "Credential Access",
            "technique_id": "T1003",
            "technique": "OS Credential Dumping"
        },
        "reporting_template": "TECHNICAL SUMMARY: [SAM / NTDS database extraction details]\nROOT CAUSE: [Extraction binary or administrative command run]\nBUSINESS IMPACT: [Organization-wide credential compromise risk]\nRECOMMENDED ACTIONS: [Rotate Kerberos tickets, execute domain credential change, block hashes]"
    },
    "phishing": {
        "name": "Phishing Attachment & Link Playbook",
        "trigger_conditions": {
            "techniques": ["T1566.001", "T1566.002"],
            "behaviors": ["outlook_spawn", "browser_phish"]
        },
        "evidence_to_collect": [
            "Email attachment filenames and file hashes", "Click history of target URLs",
            "Mail application spawning child binaries", "Browser network requests to phishing sites"
        ],
        "api_calls": [
            "get_detection_details", "get_host_details", "lookup_ioc"
        ],
        "correlation_logic": "Trace email client parent (e.g. outlook.exe) spawning office applications (e.g. excel.exe, winword.exe) or command line interpreter processes (e.g. cmd.exe, wscript.exe).",
        "decision_points": [
            "Did the user run the attachment binary?",
            "Were authentication details entered on the linked page?"
        ],
        "escalation_criteria": "Attachment execution resulting in outbound beaconing connection to unknown hosts.",
        "false_positive_checks": [
            "Check if this is an internal authorized security simulation phishing exercise",
            "Determine if the user received standard files from known partner organizations"
        ],
        "mitre_mapping": {
            "tactic": "Initial Access",
            "technique_id": "T1566.001",
            "technique": "Phishing: Spearphishing Attachment"
        },
        "reporting_template": "TECHNICAL SUMMARY: [Phishing vector analysis]\nROOT CAUSE: [Inbound email sender and file attachment]\nBUSINESS IMPACT: [Identified account compromise / system entry]\nRECOMMENDED ACTIONS: [Purge email from inboxes, revoke active sessions, isolate endpoint]"
    },
    "beaconing": {
        "name": "Beaconing Network C2 Playbook",
        "trigger_conditions": {
            "techniques": ["T1071.001"],
            "behaviors": ["beaconing", "persistent_outbound", "c2_network"]
        },
        "evidence_to_collect": [
            "Jitter and frequency of outbound sockets", "User agent strings in requests",
            "Direct external IP connections without DNS", "Unusual protocols on standard ports"
        ],
        "api_calls": [
            "get_detection_details", "get_network_events_for_detection", "lookup_ioc"
        ],
        "correlation_logic": "Analyze connection intervals of outbound sockets from host process memory space to establish beaconing behavior metrics (constant interval + minimal jitter).",
        "decision_points": [
            "Is the remote IP matched with known malicious C2 threat actor networks?",
            "Is the connection initiated by an unsigned user profile process?"
        ],
        "escalation_criteria": "Continuous, verified C2 beaconing connections established from highly secure subnet endpoints.",
        "false_positive_checks": [
            "Verify if corporate endpoints are communicating with SaaS endpoints (e.g. Teams, OneDrive)",
            "Identify if internal telemetry diagnostic loops are active"
        ],
        "mitre_mapping": {
            "tactic": "Command and Control",
            "technique_id": "T1071.001",
            "technique": "Application Layer Protocol: Web Protocols"
        },
        "reporting_template": "TECHNICAL SUMMARY: [Beacon frequency and target analysis]\nROOT CAUSE: [Malicious resident process or shellcode injection]\nBUSINESS IMPACT: [Exfiltration and operational risk level]\nRECOMMENDED ACTIONS: [Block IP/Domain at proxy, terminate process, clean persistent folders]"
    },
    "lateral_movement": {
        "name": "Lateral Movement Playbook",
        "trigger_conditions": {
            "techniques": ["T1021.002", "T1021.001"],
            "behaviors": ["wmi_exec", "remote_services", "psexec_service"]
        },
        "evidence_to_collect": [
            "WMI remote process instantiation logs", "Remote execution service installations",
            "SMB session telemetry and shared directory connections", "RDP logon events from internal assets"
        ],
        "api_calls": [
            "get_detection_details", "get_host_details", "query_incidents_by_host"
        ],
        "correlation_logic": "Map inbound network logons (Type 3 or Type 10) to remote command execution events (e.g. cmd.exe spawning under wmiprvse.exe or services.exe).",
        "decision_points": [
            "Did the remote execution command succeed?",
            "Are administrative credentials shared across endpoints?"
        ],
        "escalation_criteria": "Active, unapproved remote service installation (e.g. PsExec) traversing critical network assets.",
        "false_positive_checks": [
            "Verify if management scripts or SCCM deployment workflows are executing commands",
            "Confirm if active system administrators are executing remote maintenance tasks"
        ],
        "mitre_mapping": {
            "tactic": "Lateral Movement",
            "technique_id": "T1021.002",
            "technique": "Remote Services: SMB/Windows Admin Shares"
        },
        "reporting_template": "TECHNICAL SUMMARY: [Source and target asset movement audit]\nROOT CAUSE: [Compromised credentials used remotely]\nBUSINESS IMPACT: [Network-wide breach scope and active propagation]\nRECOMMENDED ACTIONS: [Revoke admin account, restrict admin shares, audit active logins]"
    },
    "usb_activity": {
        "name": "USB Removable Media Exfiltration Playbook",
        "trigger_conditions": {
            "techniques": ["T1567", "T1052.001"],
            "behaviors": ["usb_mount", "removable_exfil"]
        },
        "evidence_to_collect": [
            "USB device hardware model and serial number", "File write commands targeting removable volumes",
            "Sensitive catalog file matching on host prior to mount", "Mount logs in system registry"
        ],
        "api_calls": [
            "get_detection_details", "get_host_details"
        ],
        "correlation_logic": "Correlate volume mounting events with high-frequency file reads or compression actions (e.g. 7zip/tar) immediately preceding device connection.",
        "decision_points": [
            "Were sensitive business files copied to the volume?",
            "Is the USB device authorized in Falcon Device Control policies?"
        ],
        "escalation_criteria": "Detection showing copy actions of key document classifications onto unauthorized portable volumes on core endpoint workspaces.",
        "false_positive_checks": [
            "Determine if the user is copying public material or backup documentation for approved remote sites",
            "Confirm if the drive is a corporate-encrypted storage asset"
        ],
        "mitre_mapping": {
            "tactic": "Exfiltration",
            "technique_id": "T1052.001",
            "technique": "Exfiltration Over Physical Medium: Exfiltration Over USB"
        },
        "reporting_template": "TECHNICAL SUMMARY: [USB exfil analysis]\nROOT CAUSE: [User mounting portable volume and copying files]\nBUSINESS IMPACT: [Corporate intellectual property exposure risk]\nRECOMMENDED ACTIONS: [Block USB vendor ID in Device Control, request asset review]"
    },
    "cloud_workload_compromise": {
        "name": "Cloud Workload Compromise Playbook",
        "trigger_conditions": {
            "techniques": ["T1078.004"],
            "behaviors": ["metadata_access", "instance_metadata"]
        },
        "evidence_to_collect": [
            "Instance metadata endpoint requests (169.254.169.254)", "IAM role credential token extraction",
            "Container host namespace escape indicators", "Privileged docker container launches"
        ],
        "api_calls": [
            "get_detection_details", "get_host_details"
        ],
        "correlation_logic": "Analyze IMDS requests originating from non-system container processes to identify potential IAM token extraction strategies.",
        "decision_points": [
            "Did the query retrieve IAM security credentials?",
            "Are credentials used outside the cloud host region?"
        ],
        "escalation_criteria": "Active credential theft of administrative cloud roles from compromised workload hosts.",
        "false_positive_checks": [
            "Verify if regular corporate application updates check instance identity parameters",
            "Determine if deployment scanners are performing system verification"
        ],
        "mitre_mapping": {
            "tactic": "Initial Access",
            "technique_id": "T1078.004",
            "technique": "Valid Accounts: Cloud Accounts"
        },
        "reporting_template": "TECHNICAL SUMMARY: [Cloud instance compromise analysis]\nROOT CAUSE: [Exposed application service allowing metadata query]\nBUSINESS IMPACT: [Exposed cloud tenant API capabilities]\nRECOMMENDED ACTIONS: [Rotate cloud IAM roles, modify IMDS access metrics, isolate pod]"
    },
    "identity_compromise": {
        "name": "Identity & Credential Compromise Playbook",
        "trigger_conditions": {
            "techniques": ["T1110"],
            "behaviors": ["ad_bruteforce", "kerberoasting", "unusual_login"]
        },
        "evidence_to_collect": [
            "Failed logon attempts count", "Logon origin IP and geo-location",
            "Kerberos TGS request volume per service principal", "Sensitive directory searches from host"
        ],
        "api_calls": [
            "get_detection_details", "get_host_login_history"
        ],
        "correlation_logic": "Correlate Kerberos Service Ticket requests (Kerberoasting) or credential sweeping (Brute Force) with subsequent successful logons on other domain endpoints.",
        "decision_points": [
            "Has the compromised account successfully logged into multiple hosts?",
            "Is the account assigned privileged domain group credentials?"
        ],
        "escalation_criteria": "Successful privilege escalation logons targeting Active Directory Domain Controller assets.",
        "false_positive_checks": [
            "Identify if service account passwords were modified, causing systemic connection errors",
            "Verify if security team scanner tools are performing authorized auditing sweeps"
        ],
        "mitre_mapping": {
            "tactic": "Credential Access",
            "technique_id": "T1110",
            "technique": "Brute Force"
        },
        "reporting_template": "TECHNICAL SUMMARY: [Identity compromise audit]\nROOT CAUSE: [Compromised credentials or password guessing campaign]\nBUSINESS IMPACT: [User account privilege exposure level]\nRECOMMENDED ACTIONS: [Disable user account, revoke oauth tokens, reset password]"
    }
}


def match_playbook(behaviors: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """
    Scans a list of alert behaviors or techniques and returns
    the matched playbook definition from the registry.
    """
    if not behaviors:
        return None

    # Gather all techniques and filename/trigger text from behaviors
    techniques = set()
    behs_text = set()
    processes = set()

    for b in behaviors:
        tid = b.get("technique_id")
        if tid:
            techniques.add(tid)
            # Add parent technique category e.g. T1003 from T1003.001
            if "." in tid:
                techniques.add(tid.split(".")[0])
        
        tactic = b.get("tactic")
        if tactic:
            behs_text.add(tactic.lower())
        
        tech = b.get("technique")
        if tech:
            behs_text.add(tech.lower())
            
        desc = b.get("description")
        if desc:
            behs_text.add(desc.lower())
            
        filename = b.get("filename")
        if filename:
            processes.add(filename.lower())

    for playbook_id, playbook in PLAYBOOKS.items():
        trig = playbook["trigger_conditions"]
        
        # Check processes trigger
        proc_match = False
        if "processes" in trig:
            for p in trig["processes"]:
                if p.lower() in processes:
                    proc_match = True
                    break
        
        # Check techniques trigger
        tech_match = False
        if "techniques" in trig:
            for t in trig["techniques"]:
                if t in techniques:
                    tech_match = True
                    break
                    
        # Check behaviors keyword trigger
        beh_match = False
        if "behaviors" in trig:
            for keyword in trig["behaviors"]:
                for t_text in behs_text:
                    if keyword in t_text:
                        beh_match = True
                        break
                if beh_match:
                    break

        if proc_match or tech_match or beh_match:
            return playbook

    return None
