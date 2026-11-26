"""Correlate: detections that need MORE THAN ONE alert, which Wazuh can't do alone.

Impossible travel: the same user logs in successfully from two places that are too
far apart for the time between them (faster than a passenger jet). The later login
gets a `correlation.impossible_travel` block explaining why.

Batch only for now: it compares logins within one run. Wazuh mode will need the
last login per user stored between runs (see ADR 0004).
"""

import logging
from datetime import datetime

from pipeline import geo

logger = logging.getLogger(__name__)

MAX_SPEED_KMH = 1000    # faster than a passenger jet -> physically implausible
MIN_DISTANCE_KM = 500   # ignore short hops: GeoIP is only city/region accurate
SUCCESS_GROUP = "authentication_success"
TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S.%f%z"   # Wazuh: 2026-11-23T09:00:12.000+0000


def _parse_time(value):
    try:
        return datetime.strptime(value, TIMESTAMP_FORMAT)
    except (TypeError, ValueError):
        return None  # missing or malformed timestamp: can't use this login


def _place(ip, loc):
    return {"ip": ip, "country": loc["country"], "city": loc["city"]}


def detect_impossible_travel(alerts, lookup=geo.lookup):
    """Return a copy of `alerts`, each with a `correlation` dict (empty if nothing found).

    `lookup` is injectable so tests can pass a fake instead of the real GeoIP database.
    """
    out = [{**a, "correlation": {}} for a in alerts]

    # Successful logins with everything we need, oldest first.
    logins = []
    for a in out:
        when = _parse_time(a.get("timestamp"))
        if SUCCESS_GROUP in a.get("rule_groups", []) and a.get("user") and a.get("src_ip") and when:
            logins.append((when, a))
    logins.sort(key=lambda pair: pair[0])

    last_login_by_user = {}
    for when, alert in logins:
        user = alert["user"]
        previous = last_login_by_user.get(user)
        last_login_by_user[user] = (when, alert)
        if previous is None:
            continue

        prev_when, prev_alert = previous
        if prev_alert["src_ip"] == alert["src_ip"]:
            continue

        loc_from, loc_to = lookup(prev_alert["src_ip"]), lookup(alert["src_ip"])
        if not loc_from or not loc_to:
            continue  # no location for one side: can't judge

        km = geo.haversine_km(loc_from["lat"], loc_from["lon"], loc_to["lat"], loc_to["lon"])
        hours = (when - prev_when).total_seconds() / 3600
        speed = km / hours if hours > 0 else float("inf")

        if km >= MIN_DISTANCE_KM and speed > MAX_SPEED_KMH:
            alert["correlation"]["impossible_travel"] = {
                "previous_alert_id": prev_alert.get("alert_id"),
                "from": _place(prev_alert["src_ip"], loc_from),
                "to": _place(alert["src_ip"], loc_to),
                "distance_km": round(km),
                "minutes_between": round(hours * 60, 1),
                "speed_kmh": round(speed) if speed != float("inf") else None,
            }
            logger.info(
                "Impossible travel for %s: %s -> %s, %d km in %.1f min",
                user, loc_from["country"], loc_to["country"], km, hours * 60,
            )

    return out
