"""
ip_lookup.py
-------------
Enriches a bare IP address with context for the dashboard's alert detail
card: reverse DNS hostname, and organization/ASN/country via a free
lookup API (ip-api.com — no key required for non-commercial use, ~45
req/min limit, hence the cache below).

Private/link-local addresses (RFC1918, loopback, etc.) never leave the
machine for lookup — there's nothing an external API could tell you
about 192.168.x.x anyway, and it saves a wasted network call for the
most common case (your own LAN devices).

The external fetch is injected (`fetch_fn`) so this is unit-testable
without hitting the network.
"""

import ipaddress
import json
import socket
import threading
import time
import urllib.request
import urllib.error


CACHE_TTL_SECONDS = 3600  # ip-api.com data doesn't change fast; cache generously
LOOKUP_TIMEOUT_SECONDS = 2.0

_cache_lock = threading.Lock()
_cache: dict[str, tuple[float, dict]] = {}


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


def _reverse_dns(ip: str) -> str | None:
    try:
        socket.setdefaulttimeout(LOOKUP_TIMEOUT_SECONDS)
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, socket.timeout, OSError):
        return None


def _fetch_from_ip_api(ip: str) -> dict | None:
    """Default external lookup — ip-api.com free JSON endpoint.
    Returns None on any failure (offline, blocked, rate-limited) rather
    than raising — a lookup failure should degrade gracefully in the UI,
    not break the alert card."""
    url = f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,isp,org,as"
    try:
        with urllib.request.urlopen(url, timeout=LOOKUP_TIMEOUT_SECONDS) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        if data.get("status") != "success":
            return None
        return {
            "country": data.get("country"),
            "region": data.get("regionName"),
            "city": data.get("city"),
            "isp": data.get("isp"),
            "org": data.get("org"),
            "asn": data.get("as"),
        }
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        return None


def get_ip_info(ip: str, fetch_fn=None) -> dict:
    """Returns a dict describing the IP:
        {
          "ip": ...,
          "is_private": bool,
          "hostname": str | None,
          "org": str | None, "asn": str | None,
          "country": str | None, "region": str | None, "city": str | None,
          "isp": str | None,
          "cached": bool,
        }
    Never raises — every field degrades to None on lookup failure.
    """
    fetch_fn = fetch_fn or _fetch_from_ip_api

    now = time.time()
    with _cache_lock:
        entry = _cache.get(ip)
        if entry and now - entry[0] < CACHE_TTL_SECONDS:
            result = dict(entry[1])
            result["cached"] = True
            return result

    is_private = _is_private(ip)
    hostname = _reverse_dns(ip)

    if is_private:
        external = None
    else:
        external = fetch_fn(ip)

    result = {
        "ip": ip,
        "is_private": is_private,
        "hostname": hostname,
        "org": (external or {}).get("org"),
        "asn": (external or {}).get("asn"),
        "isp": (external or {}).get("isp"),
        "country": (external or {}).get("country"),
        "region": (external or {}).get("region"),
        "city": (external or {}).get("city"),
    }

    with _cache_lock:
        _cache[ip] = (now, result)

    result = dict(result)
    result["cached"] = False
    return result


def clear_cache():
    """Exposed mainly for tests."""
    with _cache_lock:
        _cache.clear()
