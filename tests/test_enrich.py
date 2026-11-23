"""Tests for the enrich step. None of these call the real API: every input is
skipped before any lookup happens."""

from pipeline.enrich import enrich


def test_invalid_ip_is_skipped_not_crashed():
    result = enrich({"src_ip": "not-an-ip"})
    assert result["intel"] == {}


def test_private_ip_is_not_looked_up():
    result = enrich({"src_ip": "192.168.1.10"})
    assert result["intel"] == {}
