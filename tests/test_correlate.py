"""Tests for impossible-travel correlation. A fake lookup dict replaces the GeoIP
database, so tests need no download and give the same answer every time."""

import pytest

from pipeline.correlate import detect_impossible_travel
from pipeline.geo import haversine_km

FAKE_GEO = {
    "1.1.1.1": {"country": "US", "city": "New York", "lat": 40.71, "lon": -74.01},
    "2.2.2.2": {"country": "NL", "city": "Amsterdam", "lat": 52.37, "lon": 4.90},
    "3.3.3.3": {"country": "US", "city": "Newark", "lat": 40.74, "lon": -74.17},  # ~15 km from NY
}


def fake_lookup(ip):
    return FAKE_GEO.get(ip)


def login(alert_id, user, ip, time, groups=("authentication_success",)):
    return {
        "alert_id": alert_id,
        "user": user,
        "src_ip": ip,
        "timestamp": f"2026-11-23T{time}.000+0000",
        "rule_groups": list(groups),
    }


def run(alerts):
    return detect_impossible_travel(alerts, lookup=fake_lookup)


def test_haversine_new_york_to_amsterdam():
    km = haversine_km(40.71, -74.01, 52.37, 4.90)
    assert km == pytest.approx(5860, rel=0.02)  # real-world figure is about 5,860 km


def test_flags_second_login_when_travel_is_impossible():
    out = run([login("a", "jdoe", "1.1.1.1", "09:00:00"), login("b", "jdoe", "2.2.2.2", "09:11:00")])

    assert out[0]["correlation"] == {}                     # first login is not suspicious
    hit = out[1]["correlation"]["impossible_travel"]
    assert hit["previous_alert_id"] == "a"
    assert hit["from"]["country"] == "US" and hit["to"]["country"] == "NL"
    assert hit["minutes_between"] == 11.0
    assert hit["speed_kmh"] > 1000


def test_order_of_input_does_not_matter():
    # Same two logins, given newest first: still the 09:11 login gets flagged.
    out = run([login("b", "jdoe", "2.2.2.2", "09:11:00"), login("a", "jdoe", "1.1.1.1", "09:00:00")])
    assert "impossible_travel" in out[0]["correlation"]
    assert out[1]["correlation"] == {}


def test_plausible_travel_is_not_flagged():
    # US -> NL in 10 hours is ~590 km/h: possible by plane.
    out = run([login("a", "jdoe", "1.1.1.1", "08:00:00"), login("b", "jdoe", "2.2.2.2", "18:00:00")])
    assert all(a["correlation"] == {} for a in out)


def test_short_distance_is_ignored_even_if_fast():
    # NY -> Newark (~15 km) in 1 minute: GeoIP noise, not travel.
    out = run([login("a", "jdoe", "1.1.1.1", "09:00:00"), login("b", "jdoe", "3.3.3.3", "09:01:00")])
    assert all(a["correlation"] == {} for a in out)


def test_different_users_are_not_compared():
    out = run([login("a", "jdoe", "1.1.1.1", "09:00:00"), login("b", "asmith", "2.2.2.2", "09:05:00")])
    assert all(a["correlation"] == {} for a in out)


def test_failed_logins_are_ignored():
    failed = ("authentication_failures",)
    out = run([login("a", "jdoe", "1.1.1.1", "09:00:00"), login("b", "jdoe", "2.2.2.2", "09:05:00", failed)])
    assert all(a["correlation"] == {} for a in out)


def test_unknown_location_or_bad_timestamp_is_skipped():
    alerts = [
        login("a", "jdoe", "1.1.1.1", "09:00:00"),
        login("b", "jdoe", "9.9.9.9", "09:05:00"),           # not in FAKE_GEO
        {**login("c", "jdoe", "2.2.2.2", "09:06:00"), "timestamp": "garbage"},
    ]
    out = run(alerts)
    assert all(a["correlation"] == {} for a in out)


def test_every_alert_gets_a_correlation_key_and_input_is_not_modified():
    alerts = [{"alert_id": "x", "description": "not a login"}]
    out = run(alerts)
    assert out[0]["correlation"] == {}
    assert "correlation" not in alerts[0]
