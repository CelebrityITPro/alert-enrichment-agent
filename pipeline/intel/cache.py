"""SQLite cache for threat-intel lookups.

The same attacker IP can appear in hundreds of alerts; caching means one API call
instead of hundreds, which keeps us inside free-tier rate limits.
Stores raw provider responses so new fields can be used later without re-fetching.
"""

import json
import sqlite3
import time
from pathlib import Path
from contextlib import closing

DB_PATH = Path("data/intel_cache.sqlite")  # data/ is gitignored
TTL_SECONDS = 24 * 60 * 60  # reputation changes, so results expire after 24h


def _connect():
    """Open the cache database, creating the folder and table on first use."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS cache (
            provider   TEXT,
            indicator  TEXT,
            result     TEXT,
            fetched_at REAL,
            PRIMARY KEY (provider, indicator)
        )
    """)
    return conn


def get_cached(provider, indicator):
    """Return the cached raw result as a dict, or None if missing or expired."""
    # closing(...) closes the connection; the inner `conn` commits the transaction.
    # (`with sqlite3.connect()` alone commits but does NOT close.)
    with closing(_connect()) as conn, conn:
        # `?` placeholders, never f-strings: indicators come from untrusted logs
        # and must not be able to inject SQL.
        row = conn.execute(
            "SELECT result, fetched_at FROM cache WHERE provider = ? AND indicator = ?",
            (provider, indicator),
        ).fetchone()
    if row is None:
        return None
    result, fetched_at = row
    if time.time() - fetched_at > TTL_SECONDS:
        return None  # stale: treat as a miss so the caller re-fetches
    return json.loads(result)


def save_cached(provider, indicator, result):
    """Store (or overwrite) a raw result with the current time."""
    with closing(_connect()) as conn, conn:
        conn.execute(
            "INSERT OR REPLACE INTO cache VALUES (?, ?, ?, ?)",
            (provider, indicator, json.dumps(result), time.time()),
        )
