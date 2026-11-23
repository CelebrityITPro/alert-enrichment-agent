"""Normalize: convert a raw Wazuh alert into one standard shape.

Different Wazuh rules store the same information in different places
(e.g. the user is `data.srcuser`, `data.dstuser` or `syscheck.uname_after`).
Every later step only works with the standard shape returned here.
"""


def normalize(alert):
    """Return a flat dict with the same keys for every alert type.

    Missing fields become None (or [] for mitre_ids); this function never raises
    on missing or null sections.
    """
    # `x or {}` handles both a missing key AND an explicit null (None) value.
    # `.get(key, {})` alone only handles the missing case.
    rule = alert.get("rule") or {}
    agent = alert.get("agent") or {}
    data = alert.get("data") or {}
    syscheck = alert.get("syscheck") or {}

    return {
        "source": "wazuh",
        "alert_id": alert.get("id"),
        "timestamp": alert.get("timestamp"),  # still a string; parse to datetime when needed
        "rule_id": rule.get("id"),
        "description": rule.get("description"),
        "severity": rule.get("level"),  # Wazuh scale 0-15
        "mitre_ids": (rule.get("mitre") or {}).get("id") or [],
        "host": agent.get("name"),
        "src_ip": data.get("srcip"),
        # First non-empty value wins: failed login, successful login, then file owner.
        "user": data.get("srcuser") or data.get("dstuser") or syscheck.get("uname_after"),
        "file_path": syscheck.get("path"),
        "file_sha256": syscheck.get("sha256_after"),
        # UNTRUSTED: parts of the raw log are attacker-controlled (prompt-injection risk).
        "raw_log": alert.get("full_log"),
    }
