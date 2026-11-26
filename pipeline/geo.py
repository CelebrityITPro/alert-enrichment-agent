"""IP geolocation with the offline MaxMind GeoLite2 City database.

Offline on purpose: login IPs are never sent to a third party, and there's no quota.
The .mmdb file lives in data/geo/ (gitignored). If it's missing, lookups return None
and the impossible-travel check is skipped, so fixtures mode still runs for anyone.
"""

import logging
import math
import os

import geoip2.database
import geoip2.errors
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

EARTH_RADIUS_KM = 6371.0

_reader = None          # opened once, reused for every lookup
_reader_failed = False  # remember a missing DB so we only warn once


def _get_reader():
    global _reader, _reader_failed
    if _reader is None and not _reader_failed:
        path = os.environ.get("GEOIP_DB_PATH", "data/geo/GeoLite2-City.mmdb")
        try:
            _reader = geoip2.database.Reader(path)
        except (FileNotFoundError, OSError, ValueError) as e:
            _reader_failed = True
            logger.warning("GeoIP database not available (%s): impossible-travel check skipped", e)
    return _reader


def lookup(ip):
    """Return {"country", "city", "lat", "lon"} for `ip`, or None if unknown/unavailable."""
    reader = _get_reader()
    if reader is None:
        return None
    try:
        r = reader.city(ip)
    except (geoip2.errors.AddressNotFoundError, ValueError):
        return None  # private/reserved/unknown IP, or not an IP at all
    if r.location.latitude is None or r.location.longitude is None:
        return None
    return {
        "country": r.country.iso_code,
        "city": r.city.name,
        "lat": r.location.latitude,
        "lon": r.location.longitude,
    }


def haversine_km(lat1, lon1, lat2, lon2):
    """Great-circle distance between two points on Earth, in kilometres."""
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlmb = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlmb / 2) ** 2
    return 2 * EARTH_RADIUS_KM * math.asin(math.sqrt(a))
