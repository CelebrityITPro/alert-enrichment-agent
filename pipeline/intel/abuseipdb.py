"""AbuseIPDB client: IP reputation lookups, cached in SQLite.

API docs: https://docs.abuseipdb.com (CHECK endpoint).
Requires ABUSEIPDB_API_KEY in .env (only needed on a cache miss).
"""

import logging
import os

import requests
from dotenv import load_dotenv

from pipeline.intel.cache import cached_lookup

# Load .env when running locally; in Docker, compose's env_file already sets the variables.
load_dotenv()

API_URL = "https://api.abuseipdb.com/api/v2/check"
PROVIDER = "abuseipdb"


def _fetch(ip):
    """Call the API and return AbuseIPDB's raw result. Raises on missing key or HTTP errors."""
    api_key = os.environ.get("ABUSEIPDB_API_KEY")
    if not api_key:
        raise RuntimeError("ABUSEIPDB_API_KEY environment variable is not set")

    response = requests.get(
        API_URL,
        headers={"Key": api_key, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": 90},
        timeout=10,  # never hang forever on a slow or dead API
    )
    response.raise_for_status()  # 401 bad key, 429 rate limit -> exception -> fail-soft in enrich
    return response.json()["data"]  # AbuseIPDB wraps the result in a top-level "data" key


def _summarize(ip, data):
    """Turn AbuseIPDB's raw response into our standard shape."""
    return {
        "ip": ip,
        "abuse_score": data.get("abuseConfidenceScore"),  # 0 (clean) to 100 (malicious)
        "country": data.get("countryCode"),
        "isp": data.get("isp"),
        "total_reports": data.get("totalReports"),
        "is_tor": data.get("isTor"),
        "usage_type": data.get("usageType"),
    }


def check_ip(ip):
    """Return a reputation summary for `ip`, using the cache when possible.

    Raises RuntimeError if the API key is missing, or requests.RequestException
    on network/HTTP errors (the enrich step catches both).
    """
    return cached_lookup(PROVIDER, ip, _fetch, _summarize)


if __name__ == "__main__":
    # Quick manual check: python -m pipeline.intel.abuseipdb
    logging.basicConfig(level=logging.DEBUG)
    print(check_ip("8.8.8.8"))
