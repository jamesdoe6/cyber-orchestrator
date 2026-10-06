"""MITRE ATT&CK lookup.

A small, curated technique table ships inline so the UI and reports work
offline. The update module (see app/updater.py) can refresh a fuller table
from the official ATT&CK STIX bundle into var/attack.json; when that file is
present it is merged over the built-ins.
"""
from __future__ import annotations

import json

from .config import settings

_BUILTIN: dict[str, dict] = {
    "T1595": {"name": "Active Scanning", "tactic": "Reconnaissance"},
    "T1595.002": {"name": "Vulnerability Scanning", "tactic": "Reconnaissance"},
    "T1596": {"name": "Search Open Technical Databases", "tactic": "Reconnaissance"},
    "T1593": {"name": "Search Open Websites/Domains", "tactic": "Reconnaissance"},
    "T1590": {"name": "Gather Victim Network Information", "tactic": "Reconnaissance"},
    "T1589": {"name": "Gather Victim Identity Information", "tactic": "Reconnaissance"},
    "T1046": {"name": "Network Service Discovery", "tactic": "Discovery"},
    "T1018": {"name": "Remote System Discovery", "tactic": "Discovery"},
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "T1110": {"name": "Brute Force", "tactic": "Credential Access"},
    "T1110.001": {"name": "Password Guessing", "tactic": "Credential Access"},
    "T1110.002": {"name": "Password Cracking", "tactic": "Credential Access"},
    "T1557": {"name": "Adversary-in-the-Middle", "tactic": "Credential Access"},
    "T1557.001": {"name": "LLMNR/NBT-NS Poisoning and SMB Relay", "tactic": "Credential Access"},
    "T1482": {"name": "Domain Trust Discovery", "tactic": "Discovery"},
    "T1021": {"name": "Remote Services", "tactic": "Lateral Movement"},
    "T1589.002": {"name": "Email Addresses", "tactic": "Reconnaissance"},
    "T1595.001": {"name": "Scanning IP Blocks", "tactic": "Reconnaissance"},
    "T1595.003": {"name": "Wordlist Scanning", "tactic": "Reconnaissance"},
    "T1590.001": {"name": "Domain Properties", "tactic": "Reconnaissance"},
    "T1592": {"name": "Gather Victim Host Information", "tactic": "Reconnaissance"},
    "T1087": {"name": "Account Discovery", "tactic": "Discovery"},
    "T1087.002": {"name": "Domain Account", "tactic": "Discovery"},
    "T1135": {"name": "Network Share Discovery", "tactic": "Discovery"},
    "T1518": {"name": "Software Discovery", "tactic": "Discovery"},
    "T1083": {"name": "File and Directory Discovery", "tactic": "Discovery"},
    "T1110.003": {"name": "Password Spraying", "tactic": "Credential Access"},
    "T1021.002": {"name": "SMB/Windows Admin Shares", "tactic": "Lateral Movement"},
    "T1059.005": {"name": "Visual Basic", "tactic": "Execution"},
    "T1059.007": {"name": "JavaScript", "tactic": "Execution"},
    "T1552.001": {"name": "Credentials In Files", "tactic": "Credential Access"},
    "T1005": {"name": "Data from Local System", "tactic": "Collection"},
    "T1040": {"name": "Network Sniffing", "tactic": "Credential Access / Discovery"},
    "T1593.002": {"name": "Search Engines", "tactic": "Reconnaissance"},
    "T1566.001": {"name": "Spearphishing Attachment", "tactic": "Initial Access"},
    "T1071.004": {"name": "DNS (C2)", "tactic": "Command and Control"},
    "T1518.001": {"name": "Security Software Discovery", "tactic": "Discovery"},
    "T1021.004": {"name": "SSH", "tactic": "Lateral Movement"},
    "T1014": {"name": "Rootkit", "tactic": "Defense Evasion"},
    "T1049": {"name": "System Network Connections Discovery", "tactic": "Discovery"},
    # Defensive-side mappings (what a detection covers)
    "T1071": {"name": "Application Layer Protocol", "tactic": "Command and Control"},
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution"},
    "T1078": {"name": "Valid Accounts", "tactic": "Defense Evasion / Persistence"},
}


def _load_overlay() -> dict:
    path = settings.paths_data / "attack.json"
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


_OVERLAY = _load_overlay()


def lookup(technique_id: str) -> dict:
    tid = technique_id.strip().upper()
    data = {**_BUILTIN, **_OVERLAY}
    info = data.get(tid, {"name": "Unknown technique", "tactic": "Unknown"})
    return {"id": tid, **info}


def enrich(technique_ids: list[str]) -> list[dict]:
    return [lookup(t) for t in technique_ids]
