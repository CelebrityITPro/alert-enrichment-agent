def normalize(alert):
    rule = alert.get("rule") or {}
    agent = alert.get("agent") or {}
    data = alert.get("data") or {}
    syscheck = alert.get("syscheck") or {}

    return {
        "source": "wazuh",
        "alert_id": alert.get("id"),
        "timestamp": alert.get("timestamp"),
        "rule_id": rule.get("id"),
        "description": rule.get("description"),
        "severity": rule.get("level"),
        "mitre_ids": (rule.get("mitre") or {}).get("id") or [],
        "host": agent.get("name"),
        "src_ip": data.get("srcip"),
        "user": data.get("srcuser") or data.get("dstuser") or syscheck.get("uname_after"),
        "file_path": syscheck.get("path"),
        "file_sha256": syscheck.get("sha256_after"),
        "raw_log": alert.get("full_log"),
    }


