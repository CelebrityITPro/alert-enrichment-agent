"""Enrich: attach threat-intel results to a normalized alert.

Rules:
1. Only look up public IPs (don't leak internal addresses or waste API quota).
2. Validate first: src_ip and file hashes come from logs and may be attacker-controlled garbage.
3. Fail soft: a failed lookup is recorded on the alert; the pipeline keeps going.

Providers:  IP   -> AbuseIPDB (reputation) + OTX (campaign context)
            hash -> VirusTotal (AV detections) + OTX (campaign context)
"""

import ipaddress
import logging
import re

import requests

from pipeline.intel.abuseipdb import check_ip
from pipeline.intel.virustotal import check_hash
from pipeline.intel import otx

logger = logging.getLogger(__name__)

# Exactly 64 hex characters. Also guarantees nothing odd ends up in an API URL path.
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


def _run_lookup(intel, name, lookup, value):
    """Run one provider lookup; on failure, record the error instead of raising."""
    try:
        intel[name] = lookup(value)
    except LOOKUP_ERRORS as e:
        # Network error, HTTP error (401/429...) or missing API key.
        logger.warning("%s lookup failed for %s: %s", name, value, e)
        intel[name] = {"error": str(e)}


def enrich(alert):
    """Return a copy of `alert` with an added "intel" dict of lookup results."""
    intel = {}

    ip = alert.get("src_ip")
    if ip and _is_public_ip(ip):
        _run_lookup(intel, "abuseipdb", check_ip, ip)
        _run_lookup(intel, "otx_ip", otx.check_ip, ip)

    sha256 = alert.get("file_sha256")
    if _is_sha256(sha256):
        sha256 = sha256.lower()  # one canonical form, so the cache key is always the same
        _run_lookup(intel, "virustotal", check_hash, sha256)
        _run_lookup(intel, "otx_hash", otx.check_hash, sha256)

    # Build a new dict instead of modifying the input (easier to test and debug).
    return {**alert, "intel": intel}
