"""Tests for the VirusTotal client. No real API calls: requests.get is replaced
by a fake, and the cache uses a temporary database (tmp_path)."""

import pytest
import requests

import pipeline.intel.cache
import pipeline.intel.virustotal as vt

EICAR = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


class FakeResponse:
    """Just enough of a requests.Response for our client."""

    def __init__(self, status_code, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"{self.status_code} error")


@pytest.fixture
def isolated(monkeypatch, tmp_path):
    """Temp cache + fake API key for every test, and a list recording each API call."""
    monkeypatch.setattr(pipeline.intel.cache, "DB_PATH", tmp_path / "cache.sqlite")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")
    calls = []
    return calls


def fake_get(calls, response):
    def _get(url, **kwargs):
        calls.append(url)
        return response
    return _get


def test_known_hash_is_summarized_and_cached(monkeypatch, isolated):
    payload = {"data": {"attributes": {
        "last_analysis_stats": {"malicious": 60, "suspicious": 2, "undetected": 10},
        "popular_threat_classification": {"suggested_threat_label": "eicar/test"},
        "meaningful_name": "eicar.com",
    }}}
    monkeypatch.setattr(vt.requests, "get", fake_get(isolated, FakeResponse(200, payload)))

    first = vt.check_hash(EICAR)
    second = vt.check_hash(EICAR)

    assert first["found"] is True
    assert first["malicious"] == 60
    assert first["engines_total"] == 72
    assert first["threat_label"] == "eicar/test"
    assert second == first          # cache hit returns the same shape
    assert len(isolated) == 1       # ...and only ONE real API call was made


def test_unknown_hash_is_cached_as_not_found(monkeypatch, isolated):
    monkeypatch.setattr(vt.requests, "get", fake_get(isolated, FakeResponse(404)))

    first = vt.check_hash(EICAR)
    second = vt.check_hash(EICAR)

    assert first == {"sha256": EICAR, "found": False}
    assert second == first
    assert len(isolated) == 1       # 404 was cached, not re-asked


def test_rate_limit_raises_so_enrich_can_fail_soft(monkeypatch, isolated):
    monkeypatch.setattr(vt.requests, "get", fake_get(isolated, FakeResponse(429)))

    with pytest.raises(requests.HTTPError):
        vt.check_hash(EICAR)


def test_missing_api_key_raises_clear_error(monkeypatch, isolated):
    monkeypatch.delenv("VIRUSTOTAL_API_KEY")

    with pytest.raises(RuntimeError, match="VIRUSTOTAL_API_KEY"):
        vt.check_hash(EICAR)
