"""VirusTotal client: file-hash reputation lookups, cached in SQLite.

API docs: https://docs.virustotal.com/reference/file-info (API v3, GET /files/{id}).
Requires VIRUSTOTAL_API_KEY in .env (only needed on a cache miss).

Privacy rule: we only ever send a HASH, never upload a file.
"""

import logging
import os

import requests
from dotenv import load_dotenv

from pipeline.intel.cache import NOT_FOUND, cached_lookup

load_dotenv()

API_URL = "https://www.virustotal.com/api/v3/files/{}"
PROVIDER = "virustotal"


def _fetch(sha256):
    """Call the API and return VT's raw file attributes (or NOT_FOUND). Raises on errors."""
    api_key = os.environ.get("VIRUSTOTAL_API_KEY")
    if not api_key:
        raise RuntimeError("VIRUSTOTAL_API_KEY environment variable is not set")

    response = requests.get(
        API_URL.format(sha256),
        headers={"x-apikey": api_key, "Accept": "application/json"},
        timeout=15,
    )

    # 404 = VT has never seen this file. That's an answer, not an error: it gets
    # cached so repeated unknown files don't burn the small free-tier quota.
    if response.status_code == 404:
        return NOT_FOUND

    response.raise_for_status()  # 401 bad key, 429 rate limit -> exception -> fail-soft in enrich
    return response.json()["data"]["attributes"]


def _summarize(sha256, attrs):
    """Turn VT's raw file attributes into our standard shape."""
    if attrs.get("_not_found"):
        return {"sha256": sha256, "found": False}

    stats = attrs.get("last_analysis_stats") or {}
    return {
        "sha256": sha256,
        "found": True,
        "malicious": stats.get("malicious"),      # engines that flagged it as malicious
        "suspicious": stats.get("suspicious"),
        "engines_total": sum(v for v in stats.values() if isinstance(v, int)),
        "threat_label": (attrs.get("popular_threat_classification") or {}).get("suggested_threat_label"),
        "name": attrs.get("meaningful_name"),
        "file_type": attrs.get("type_description"),
        "reputation": attrs.get("reputation"),     # VT community score (votes, not engines)
    }


def check_hash(sha256):
    """Return a reputation summary for a SHA256 hash, using the cache when possible.

    The caller must pass a validated, lowercase SHA256 (enrich.py does this).
    Raises RuntimeError if the API key is missing, or requests.RequestException on
    network/HTTP errors such as 429 rate limit (the enrich step catches both).
    """
    return cached_lookup(PROVIDER, sha256, _fetch, _summarize)


if __name__ == "__main__":
    # Quick manual check with the EICAR test file hash: python -m pipeline.intel.virustotal
    logging.basicConfig(level=logging.DEBUG)
    print(check_hash("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"))
