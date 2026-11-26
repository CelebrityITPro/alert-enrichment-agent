"""Tests for the enrich step. None of these call the real API: invalid/private IPs
are skipped before any lookup, and every provider is replaced with a fake."""

import pytest
import requests

import pipeline.enrich
import pipeline.intel.otx
from pipeline.enrich import enrich


@pytest.fixture(autouse=True)
def stub_otx(monkeypatch):
    """Default fake for OTX in every test here. enrich.py calls `otx.check_ip`
    through the module, so we patch the attribute on that module."""
    monkeypatch.setattr(pipeline.intel.otx, "check_ip", lambda ip: {"stub": "otx_ip"})
    monkeypatch.setattr(pipeline.intel.otx, "check_hash", lambda h: {"stub": "otx_hash"})


def test_public_ip_gets_both_ip_providers(monkeypatch):
    monkeypatch.setattr(pipeline.enrich, "check_ip", lambda ip: {"stub": "abuseipdb"})
    result = enrich({"src_ip": "8.8.8.8"})
    assert set(result["intel"]) == {"abuseipdb", "otx_ip"}


def test_hash_gets_both_hash_providers(monkeypatch):
    monkeypatch.setattr(pipeline.enrich, "check_hash", lambda h: {"stub": "virustotal"})
    result = enrich({"file_sha256": "a" * 64})
    assert set(result["intel"]) == {"virustotal", "otx_hash"}


def test_one_provider_failing_does_not_affect_the_other(monkeypatch):
    def otx_down(ip):
        raise requests.Timeout("OTX timed out")

    monkeypatch.setattr(pipeline.enrich, "check_ip", lambda ip: {"abuse_score": 100})
    monkeypatch.setattr(pipeline.intel.otx, "check_ip", otx_down)

    intel = enrich({"src_ip": "8.8.8.8"})["intel"]
    assert intel["abuseipdb"] == {"abuse_score": 100}
    assert intel["otx_ip"] == {"error": "OTX timed out"}


def test_invalid_ip_is_skipped_not_crashed():
    result = enrich({"src_ip": "not-an-ip"})
    assert result["intel"] == {}


def test_private_ip_is_not_looked_up():
    result = enrich({"src_ip": "192.168.1.10"})
    assert result["intel"] == {}


def test_public_ip_gets_abuseipdb_result(monkeypatch):
    def fake_check_ip(ip):
        # 999 is an impossible real score, so if we see it we KNOW the fake ran.
        return {"ip": ip, "abuse_score": 999}

    # Patch where check_ip is USED (pipeline.enrich), not where it's defined:
    # enrich.py did `from ... import check_ip`, so it holds its own reference.
    monkeypatch.setattr(pipeline.enrich, "check_ip", fake_check_ip)

    result = enrich({"src_ip": "8.8.8.8"})
    assert result["intel"]["abuseipdb"]["abuse_score"] == 999


def test_api_failure_is_recorded_not_raised(monkeypatch):
    def fake_check_ip(ip):
        # ConnectionError is a child of RequestException, so enrich() catches it.
        raise requests.ConnectionError("API is down")

    monkeypatch.setattr(pipeline.enrich, "check_ip", fake_check_ip)

    result = enrich({"src_ip": "8.8.8.8"})  # must NOT raise
    assert result["intel"]["abuseipdb"] == {"error": "API is down"}


def test_valid_hash_gets_virustotal_result_lowercased(monkeypatch):
    seen = []

    def fake_check_hash(sha256):
        seen.append(sha256)
        return {"sha256": sha256, "found": True, "malicious": 999}

    monkeypatch.setattr(pipeline.enrich, "check_hash", fake_check_hash)

    result = enrich({"file_sha256": "A" * 64})
    assert result["intel"]["virustotal"]["malicious"] == 999
    assert seen == ["a" * 64]  # normalized to lowercase before lookup/caching


def test_invalid_hash_is_skipped(monkeypatch):
    def must_not_be_called(sha256):
        raise AssertionError("check_hash should not be called for an invalid hash")

    monkeypatch.setattr(pipeline.enrich, "check_hash", must_not_be_called)

    for bad in ["not-a-hash", "abc123", "g" * 64, "../../etc/passwd", None, 12345]:
        assert enrich({"file_sha256": bad})["intel"] == {}


def test_virustotal_failure_is_recorded_not_raised(monkeypatch):
    def fake_check_hash(sha256):
        raise requests.HTTPError("429 Too Many Requests")

    monkeypatch.setattr(pipeline.enrich, "check_hash", fake_check_hash)

    result = enrich({"file_sha256": "a" * 64})
    assert result["intel"]["virustotal"] == {"error": "429 Too Many Requests"}


def test_original_alert_fields_are_kept(monkeypatch):
    monkeypatch.setattr(pipeline.enrich, "check_ip", lambda ip: {"abuse_score": 1})

    alert = {"src_ip": "8.8.8.8", "description": "test alert"}
    result = enrich(alert)

    assert result["description"] == "test alert"  # existing fields copied over
    assert "intel" not in alert                   # input dict was not modified
