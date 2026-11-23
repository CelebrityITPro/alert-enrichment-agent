import json
from pathlib import Path

from pipeline.normalize import normalize

FIXTURES = Path(__file__).parent.parent / "fixtures" / "wazuh"


def load(name):
    with open(FIXTURES / name, encoding="utf-8") as f:
        return json.load(f)


def test_bruteforce_extracts_ip_and_user():
    n = normalize(load("ssh_bruteforce_001.json"))
    assert n["src_ip"] == "203.0.113.45"
    assert n["user"] == "admin"


def test_malware_extracts_file_hash():
    n = normalize(load("malware_eicar_001.json"))
    assert n["file_sha256"] == "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    assert n["src_ip"] is None


def test_login_success_uses_dstuser():
    n = normalize(load("impossible_travel_001a.json"))
    assert n["user"] == "jdoe"


def test_empty_alert_does_not_crash():
    n = normalize({})
    assert n["src_ip"] is None
    assert n["mitre_ids"] == []
    assert set(n.keys()) == {"source","alert_id","timestamp","rule_id","description","severity",
                                "mitre_ids","host","src_ip","user","file_path","file_sha256","raw_log"}


def test_null_sections_do_not_crash():
    n = normalize({"rule": None, "data": None, "syscheck": None, "agent": None})
    assert n["src_ip"] is None
    assert n["mitre_ids"] == []