"""Shared pytest setup, applied to EVERY test automatically (autouse).

1. Temporary cache database: tests never read or write the real data/ cache.
   (Otherwise a real cache hit could hide an accidental API call.)
2. Real network calls are blocked: if any code reaches requests.get without a test
   faking it, the test fails loudly. AssertionError is used on purpose because the
   pipeline's fail-soft code catches RequestException/RuntimeError, not this.
"""

import pytest
import requests

import pipeline.intel.cache


@pytest.fixture(autouse=True)
def temp_cache(monkeypatch, tmp_path):
    monkeypatch.setattr(pipeline.intel.cache, "DB_PATH", tmp_path / "test_cache.sqlite")


@pytest.fixture(autouse=True)
def block_network(monkeypatch):
    def no_network(*args, **kwargs):
        raise AssertionError(f"Real network call attempted in a test: {args[:1]}")

    monkeypatch.setattr(requests, "get", no_network)
