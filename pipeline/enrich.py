"""Enrich: attach threat-intel results to a normalized alert.

Rules:
1. Only look up public IPs (don't leak internal addresses or waste API quota).
2. Validate first: src_ip comes from logs and may be attacker-controlled garbage.
3. Fail soft: a failed lookup is recorded on the alert; the pipeline keeps going.
"""

import ipaddress

import requests

from pipeline.intel.abuseipdb import check_ip


def _is_public_ip(value):
    """True only for a valid, internet-routable IP address."""
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        # Not an IP at all (e.g. "not-an-ip"): skip it, never crash.
        return False


def enrich(alert):
    """Return a copy of `alert` with an added "intel" dict of lookup results."""
    intel = {}
    ip = alert.get("src_ip")

    if ip and _is_public_ip(ip):
        try:
            intel["abuseipdb"] = check_ip(ip)
        except (requests.RequestException, RuntimeError) as e:
            # Network error, HTTP error (401/429...) or missing API key.
            intel["abuseipdb"] = {"error": str(e)}

    # Build a new dict instead of modifying the input (easier to test and debug).
    return {**alert, "intel": intel}
