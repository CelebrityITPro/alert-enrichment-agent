"""Enrich: attach threat-intel results to a normalized alert.

Rules:
1. Only look up public IPs (don't leak internal addresses or waste API quota).
2. Validate first: src_ip and file hashes come from logs and may be attacker-controlled garbage.
3. Fail soft: a failed lookup is recorded on the alert; the pipeline keeps going.
"""

import ipaddress
import logging
import re

import requests

from pipeline.intel.abuseipdb import check_ip
from pipeline.intel.virustotal import check_hash

logger = logging.getLogger(__name__)

# Exactly 64 hex characters. Also guarantees nothing odd ends up in the VT URL path.
SHA256_RE = re.compile(r"[0-9a-fA-F]{64}")

# Errors that mean "this lookup failed", not "the pipeline is broken".
LOOKUP_ERRORS = (requests.RequestException, RuntimeError)


def _is_public_ip(value):
    """True only for a valid, internet-routable IP address."""
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        # Not an IP at all (e.g. "not-an-ip"): skip it, never crash.
        return False


def _is_sha256(value):
    """True only for a string of exactly 64 hex characters."""
    return isinstance(value, str) and SHA256_RE.fullmatch(value) is not None


def enrich(alert):
    """Return a copy of `alert` with an added "intel" dict of lookup results."""
    intel = {}

    ip = alert.get("src_ip")
    if ip and _is_public_ip(ip):
        try:
            intel["abuseipdb"] = check_ip(ip)
        except LOOKUP_ERRORS as e:
            # Network error, HTTP error (401/429...) or missing API key.
            logger.warning("AbuseIPDB lookup failed for %s: %s", ip, e)
            intel["abuseipdb"] = {"error": str(e)}

    sha256 = alert.get("file_sha256")
    if _is_sha256(sha256):
        sha256 = sha256.lower()  # one canonical form, so the cache key is always the same
        try:
            intel["virustotal"] = check_hash(sha256)
        except LOOKUP_ERRORS as e:
            logger.warning("VirusTotal lookup failed for %s: %s", sha256, e)
            intel["virustotal"] = {"error": str(e)}

    # Build a new dict instead of modifying the input (easier to test and debug).
    return {**alert, "intel": intel}
