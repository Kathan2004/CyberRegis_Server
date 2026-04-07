"""
MITRE ATT&CK Mapping Service
Provides techniques, tactics, and mapping for security findings.
Uses a comprehensive embedded dataset of key ATT&CK techniques.
"""
from typing import Optional, List, Dict

# ─── Tactics ────────────────────────────────────────────────
TACTICS = [
    {"id": "TA0043", "name": "Reconnaissance", "description": "Gathering information to plan future operations"},
    {"id": "TA0042", "name": "Resource Development", "description": "Establishing resources to support operations"},
    {"id": "TA0001", "name": "Initial Access", "description": "Trying to get into your network"},
    {"id": "TA0002", "name": "Execution", "description": "Trying to run malicious code"},
    {"id": "TA0003", "name": "Persistence", "description": "Trying to maintain foothold"},
    {"id": "TA0004", "name": "Privilege Escalation", "description": "Trying to gain higher-level permissions"},
    {"id": "TA0005", "name": "Defense Evasion", "description": "Trying to avoid being detected"},
    {"id": "TA0006", "name": "Credential Access", "description": "Stealing credentials"},
    {"id": "TA0007", "name": "Discovery", "description": "Trying to figure out your environment"},
    {"id": "TA0008", "name": "Lateral Movement", "description": "Moving through your environment"},
    {"id": "TA0009", "name": "Collection", "description": "Gathering data of interest"},
    {"id": "TA0011", "name": "Command and Control", "description": "Communicating with compromised systems"},
    {"id": "TA0010", "name": "Exfiltration", "description": "Stealing data"},
    {"id": "TA0040", "name": "Impact", "description": "Manipulate, interrupt, or destroy systems"},
]

# ─── Key Techniques (embedded subset for offline use) ───────
TECHNIQUES = [
    {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access",
     "description": "Adversaries may exploit vulnerabilities in internet-facing applications to gain access.",
     "mitigations": ["Application Isolation", "Exploit Protection", "Network Segmentation", "Update Software"],
     "detection": ["Application logs", "Network IDS", "WAF logs"]},
    {"id": "T1566", "name": "Phishing", "tactic": "Initial Access",
     "description": "Adversaries may send phishing messages to gain access to victim systems.",
     "mitigations": ["User Training", "Email Filtering", "DMARC/DKIM/SPF", "Antivirus"],
     "detection": ["Email gateway logs", "User reports", "URL analysis"]},
    {"id": "T1566.001", "name": "Spearphishing Attachment", "tactic": "Initial Access",
     "description": "Targeted emails with malicious attachments.",
     "mitigations": ["Attachment filtering", "Sandboxing", "User awareness"],
     "detection": ["Email gateway", "Endpoint detection", "File analysis"]},
    {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution",
     "description": "Adversaries may abuse command and script interpreters to execute commands.",
     "mitigations": ["Disable Script Execution", "Application Allowlisting", "Code Signing"],
     "detection": ["Process monitoring", "Command-line logging", "Script Block Logging"]},
    {"id": "T1053", "name": "Scheduled Task/Job", "tactic": "Persistence",
     "description": "Adversaries may abuse task scheduling to execute malicious code at system startup or on a schedule.",
     "mitigations": ["Privileged Account Management", "Audit", "User Account Management"],
     "detection": ["Process/service monitoring", "Scheduled task logs", "File monitoring"]},
    {"id": "T1078", "name": "Valid Accounts", "tactic": "Persistence",
     "description": "Adversaries may obtain and abuse credentials of existing accounts.",
     "mitigations": ["MFA", "Password policies", "Privileged Account Management", "Account monitoring"],
     "detection": ["Login anomalies", "Account access logs", "Impossible travel"]},
    {"id": "T1557", "name": "Adversary-in-the-Middle", "tactic": "Credential Access",
     "description": "Adversaries may attempt to position themselves between communication endpoints to intercept data.",
     "mitigations": ["Encryption", "Network Segmentation", "SSL/TLS Inspection", "HSTS"],
     "detection": ["Network monitoring", "Packet capture", "SSL certificate anomalies"]},
    {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access",
     "description": "Adversaries may use brute force techniques to attempt access to accounts.",
     "mitigations": ["Account Lockout", "MFA", "Rate Limiting", "Password Policies"],
     "detection": ["Authentication logs", "Failed login monitoring", "Account lockout alerts"]},
    {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery",
     "description": "Adversaries may attempt to get a listing of services running on remote hosts.",
     "mitigations": ["Network Segmentation", "Firewall Rules", "Disable Unnecessary Services"],
     "detection": ["Network flow data", "Port scan detection", "IDS signatures"]},
    {"id": "T1595", "name": "Active Scanning", "tactic": "Reconnaissance",
     "description": "Adversaries may execute active reconnaissance scans to gather information.",
     "mitigations": ["Pre-compromise mitigation is difficult", "Rate limiting", "Monitoring"],
     "detection": ["Network monitoring", "IDS", "Firewall logs"]},
    {"id": "T1018", "name": "Remote System Discovery", "tactic": "Discovery",
     "description": "Adversaries may attempt to get a listing of other systems by IP address, hostname, or other identifier.",
     "mitigations": ["Network Segmentation", "Limit Access"],
     "detection": ["Process monitoring", "Network monitoring"]},
    {"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control",
     "description": "Adversaries may communicate using application layer protocols like HTTP/S, DNS.",
     "mitigations": ["Network Intrusion Prevention", "SSL/TLS Inspection"],
     "detection": ["Network monitoring", "Packet inspection", "DNS logs"]},
    {"id": "T1048", "name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration",
     "description": "Adversaries may steal data by exfiltrating it over a different protocol.",
     "mitigations": ["Network Segmentation", "DLP", "Filter network traffic"],
     "detection": ["Network monitoring", "DLP alerts", "Anomalous traffic"]},
    {"id": "T1583", "name": "Acquire Infrastructure", "tactic": "Resource Development",
     "description": "Adversaries may buy, lease, or rent infrastructure for use during targeting.",
     "mitigations": ["Pre-compromise — difficult to mitigate"],
     "detection": ["Domain registration monitoring", "Certificate transparency logs"]},
    {"id": "T1584.001", "name": "Domains", "tactic": "Resource Development",
     "description": "Adversaries may acquire domains to use during targeting.",
     "mitigations": ["Domain monitoring", "Brand protection services"],
     "detection": ["WHOIS monitoring", "Certificate transparency", "Passive DNS"]},
    {"id": "T1133", "name": "External Remote Services", "tactic": "Initial Access",
     "description": "Adversaries may leverage external-facing remote services to initially access a network.",
     "mitigations": ["MFA", "Network Segmentation", "Limit Remote Access"],
     "detection": ["Authentication logs", "VPN logs", "Network flow data"]},
    {"id": "T1498", "name": "Network Denial of Service", "tactic": "Impact",
     "description": "Adversaries may perform Network Denial of Service (DDoS) attacks.",
     "mitigations": ["DDoS protection services", "Rate limiting", "Network filtering"],
     "detection": ["Network monitoring", "Traffic analysis", "Baseline deviations"]},
    {"id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact",
     "description": "Adversaries may encrypt data on target systems to interrupt availability (ransomware).",
     "mitigations": ["Data Backup", "Behavior Prevention", "User Training"],
     "detection": ["File monitoring", "Process monitoring", "Behavioral analysis"]},
    {"id": "T1027", "name": "Obfuscated Files or Information", "tactic": "Defense Evasion",
     "description": "Adversaries may attempt to make an executable or file difficult to analyze.",
     "mitigations": ["Antivirus", "Behavior-based detection"],
     "detection": ["File analysis", "Sandbox detonation", "Behavioral detection"]},
    {"id": "T1087", "name": "Account Discovery", "tactic": "Discovery",
     "description": "Adversaries may attempt to get a listing of valid accounts or email addresses.",
     "mitigations": ["Operating System Configuration", "Network Segmentation"],
     "detection": ["Process monitoring", "API monitoring", "Log analysis"]},
]


def get_tactics() -> List[Dict]:
    """Return all MITRE ATT&CK tactics."""
    return TACTICS


def get_techniques(tactic: str = None, search: str = None) -> List[Dict]:
    """Return techniques, optionally filtered by tactic or search term."""
    results = TECHNIQUES
    if tactic:
        results = [t for t in results if tactic.lower() in t["tactic"].lower()]
    if search:
        search_lower = search.lower()
        results = [t for t in results if
                   search_lower in t["name"].lower() or
                   search_lower in t["description"].lower() or
                   search_lower in t["id"].lower()]
    return results


def get_technique_detail(technique_id: str) -> Optional[Dict]:
    """Get detailed info for a specific technique."""
    for t in TECHNIQUES:
        if t["id"].upper() == technique_id.upper():
            return t
    return None


def map_finding_to_techniques(finding_type: str, details: dict = None) -> List[Dict]:
    """Map a security finding to relevant MITRE ATT&CK techniques."""
    mapping = {
        "open_port": ["T1046", "T1595"],
        "missing_ssl": ["T1557"],
        "missing_dmarc": ["T1566"],
        "missing_spf": ["T1566"],
        "missing_waf": ["T1190"],
        "weak_headers": ["T1190"],
        "brute_force": ["T1110"],
        "malicious_ip": ["T1071", "T1048"],
        "phishing_url": ["T1566", "T1566.001"],
        "ransomware": ["T1486"],
        "dns_issue": ["T1584.001"],
    }

    technique_ids = mapping.get(finding_type, [])
    return [t for t in TECHNIQUES if t["id"] in technique_ids]
