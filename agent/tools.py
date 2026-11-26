"""Tools the agent may call while analysing an alert.

Kept deliberately small (ADR 0007): enrichment and correlation already ran in the
pipeline, so the agent only needs tools that add context it doesn't have:
- related_alerts: other alerts in this batch with the same IP, user or host
- map_mitre:      name and tactic for a MITRE ATT&CK technique ID (offline table)

Tools are read-only. The agent can never change anything; it only recommends.

Tools always return a non-empty JSON string: some providers (Groq) reject a tool
result whose content is empty, e.g. an empty list when nothing matched.
"""

import json

from langchain_core.tools import tool

from agent.prepare import alert_for_llm

MAX_RELATED = 10

# Small offline table for the techniques our scenarios involve. Offline on purpose:
# no extra API calls, and the agent can't be steered to fetch arbitrary URLs.
MITRE_TECHNIQUES = {
    "T1110": ("Brute Force", ["Credential Access"]),
    "T1110.001": ("Brute Force: Password Guessing", ["Credential Access"]),
    "T1110.003": ("Brute Force: Password Spraying", ["Credential Access"]),
    "T1078": ("Valid Accounts", ["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"]),
    "T1136": ("Create Account", ["Persistence"]),
    "T1136.001": ("Create Account: Local Account", ["Persistence"]),
    "T1098": ("Account Manipulation", ["Persistence", "Privilege Escalation"]),
    "T1098.004": ("Account Manipulation: SSH Authorized Keys", ["Persistence", "Privilege Escalation"]),
    "T1053": ("Scheduled Task/Job", ["Execution", "Persistence", "Privilege Escalation"]),
    "T1053.003": ("Scheduled Task/Job: Cron", ["Execution", "Persistence", "Privilege Escalation"]),
    "T1021.004": ("Remote Services: SSH", ["Lateral Movement"]),
    "T1059": ("Command and Scripting Interpreter", ["Execution"]),
    "T1105": ("Ingress Tool Transfer", ["Command and Control"]),
    "T1204": ("User Execution", ["Execution"]),
    "T1046": ("Network Service Discovery", ["Discovery"]),
    "T1595": ("Active Scanning", ["Reconnaissance"]),
}


def make_tools(batch, current_alert_id):
    """Build the tools for one alert. `batch` is the list of enriched alerts in this run."""

    @tool
    def related_alerts(src_ip: str = "", user: str = "", host: str = "") -> str:
        """Find other alerts in this batch that share the given source IP, user or host.
        Use it to check whether this alert is part of a wider pattern. Pass at least one value."""
        wanted = {"src_ip": src_ip.strip(), "user": user.strip(), "host": host.strip()}
        wanted = {k: v for k, v in wanted.items() if v}
        if not wanted:
            return json.dumps({"related_alerts": [], "note": "No src_ip, user or host given."})
        matches = []
        for a in batch:
            if a.get("alert_id") == current_alert_id:
                continue
            if any(a.get(k) == v for k, v in wanted.items()):
                view = alert_for_llm(a)
                matches.append({k: view.get(k) for k in
                                ("alert_id", "timestamp", "description", "src_ip", "user", "host")
                                if view.get(k) is not None})
            if len(matches) >= MAX_RELATED:
                break
        return json.dumps({"related_alerts": matches, "count": len(matches)})

    @tool
    def map_mitre(technique_id: str) -> str:
        """Look up the name and tactics of a MITRE ATT&CK technique ID such as T1110."""
        tid = technique_id.strip().upper()
        if tid not in MITRE_TECHNIQUES:
            return json.dumps({"technique_id": tid, "found": False})
        name, tactics = MITRE_TECHNIQUES[tid]
        return json.dumps({"technique_id": tid, "found": True, "name": name, "tactics": tactics})

    return [related_alerts, map_mitre]
