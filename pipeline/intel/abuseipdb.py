"""AbuseIPDB client: IP reputation lookups, cached in SQLite.

API docs: https://docs.abuseipdb.com (CHECK endpoint).
Requires ABUSEIPDB_API_KEY in .env (only needed on a cache miss).
"""

import os

import requests
from dotenv import load_dotenv

from pipeline.intel.cache import get_cached, save_cached

# Load .env when running locally; in Docker, compose's env_file already sets the variables.
load_dotenv()

API_URL = "https://api.abuseipdb.com/api/v2/check"


def _summarize(ip, data):
    """Turn AbuseIPDB's raw response into our standard shape.

    The only place that decides the output shape, so cache hits and misses
    always return the same keys.
    """
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
    # Cache first: a hit costs no API quota and works without an API key.
    cached_result = get_cached("abuseipdb", ip)
    if cached_result is not None:
        print(f"Cache hit for {ip}")
        return _summarize(ip, cached_result)

    print(f"Cache miss for {ip}")

    api_key = os.environ.get("ABUSEIPDB_API_KEY")
    if not api_key:
        raise RuntimeError("ABUSEIPDB_API_KEY environment variable is not set")

    response = requests.get(
        API_URL,
        headers={"Key": api_key, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": 90},
        timeout=10,  # never hang forever on a slow or dead API
    )
    response.raise_for_status()  # turn HTTP errors (401 bad key, 429 rate limit) into exceptions
    data = response.json()["data"]  # AbuseIPDB wraps the result in a top-level "data" key

    # Cache the RAW response; _summarize shapes it on the way out.
    save_cached("abuseipdb", ip, data)

    return _summarize(ip, data)


if __name__ == "__main__":
    # Quick manual check: python -m pipeline.intel.abuseipdb
    print(check_ip("8.8.8.8"))
