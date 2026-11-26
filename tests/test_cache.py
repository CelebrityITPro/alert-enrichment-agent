"""Tests for the shared cached_lookup() helper (temp cache comes from conftest.py)."""

import pytest

import pipeline.intel.cache as cache


def make_fetch(calls, result):
    def fetch(key):
        calls.append(key)
        return result
    return fetch


def summarize(key, raw):
    return {"key": key, "value": raw.get("value")}


def test_miss_then_hit_calls_fetch_once_and_returns_same_shape():
    calls = []
    fetch = make_fetch(calls, {"value": 42, "extra": "raw field"})

    first = cache.cached_lookup("demo", "k1", fetch, summarize)
    second = cache.cached_lookup("demo", "k1", fetch, summarize)

    assert first == second == {"key": "k1", "value": 42}
    assert calls == ["k1"]


def test_providers_do_not_share_entries():
    calls = []
    fetch = make_fetch(calls, {"value": 1})
    cache.cached_lookup("provider_a", "same-key", fetch, summarize)
    cache.cached_lookup("provider_b", "same-key", fetch, summarize)
    assert len(calls) == 2


def test_expired_entry_is_fetched_again(monkeypatch):
    calls = []
    fetch = make_fetch(calls, {"value": 1})
    cache.cached_lookup("demo", "k1", fetch, summarize)

    monkeypatch.setattr(cache, "TTL_SECONDS", -1)  # everything is now "stale"
    cache.cached_lookup("demo", "k1", fetch, summarize)

    assert len(calls) == 2


def test_fetch_error_is_not_cached():
    def failing_fetch(key):
        raise RuntimeError("API down")

    with pytest.raises(RuntimeError):
        cache.cached_lookup("demo", "k1", failing_fetch, summarize)

    assert cache.get_cached("demo", "k1") is None  # next run will retry


def test_sql_injection_attempt_is_stored_as_plain_data():
    evil = "x'); DROP TABLE cache; --"
    cache.save_cached("demo", evil, {"value": 1})
    assert cache.get_cached("demo", evil) == {"value": 1}  # table still exists
