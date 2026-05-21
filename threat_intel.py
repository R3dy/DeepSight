#!/usr/bin/env python3
"""
DeepSight Threat Intelligence Integration Module

Fetchers for external threat feeds and a background collector that
cross-references observed IPs/domains against known threats.

Sources:
  - AbuseIPDB (IP reputation, API key required)
  - AlienVault OTX (community pulses, API key optional for public data)
  - URLhaus (malware URLs, public — abuse.ch)
  - Feodo Tracker (C2 blocklists, public — abuse.ch)
  - Tor exit nodes (public list from Tor Project)

All fetchers degrade gracefully: API-key sources skip if unconfigured;
public sources work out of the box.
"""

import json
import os
import time
import threading
import socket
import logging
from collections import defaultdict
from datetime import datetime, timezone

# ── Optional notification integration ──
try:
    from notifier import dispatch_alert as _dispatch_notification
except ImportError:
    def _dispatch_notification(alert):
        pass

# ═══════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════

# API keys (set via environment variables)
ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
OTX_KEY = os.environ.get("OTX_API_KEY", "")

# Refresh intervals (seconds)
INTERVAL_ABUSEIPDB = 3600   # 1h — free tier: 1000/day
INTERVAL_OTX = 3600         # 1h
INTERVAL_URLHAUS = 900      # 15min
INTERVAL_FEODO = 900        # 15min
INTERVAL_TOR = 3600         # 1h
INTERVAL_CROSS_REFERENCE = 300  # 5min — check observed IPs against loaded intel

# Cache lifetimes
CACHE_TTL = {
    "abuseipdb": 3600,
    "otx": 3600,
    "urlhaus": 900,
    "feodo": 900,
    "tor": 3600,
}

# Alert severity mapping for threat intel matches
THREAT_SEVERITY = {
    "abuseipdb": "high",
    "otx": "high",
    "urlhaus": "critical",
    "feodo": "high",
    "tor": "medium",
}

# HTTP request timeout
REQUEST_TIMEOUT = 15

# ── Internal state ──
_intel_cache = {}          # source -> {data, ts}
_observed_ips = {}         # ip -> {last_seen, host}
_observed_domains = {}     # domain -> {last_seen, host}
_lock = threading.Lock()
_collector_running = False
_log = logging.getLogger("threat_intel").info

# ═══════════════════════════════════════════
# Utility Functions
# ═══════════════════════════════════════════

def _fetch_url(url, headers=None, timeout=REQUEST_TIMEOUT):
    """Fetch a URL and return parsed JSON or text, or None on failure."""
    try:
        from urllib.request import Request, urlopen
        req = Request(url, headers=headers or {})
        req.add_header("User-Agent", "DeepSight/1.0 (+https://github.com/R3dy/DeepSight)")
        with urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            ct = resp.headers.get("Content-Type", "")
            if "json" in ct:
                return json.loads(body)
            return body
    except Exception as e:
        _log(f"Fetch error for {url}: {e}")
        return None


def _cache_get(source):
    """Get cached intel if not expired."""
    with _lock:
        entry = _intel_cache.get(source)
        if entry and (time.time() - entry["ts"]) < CACHE_TTL.get(source, 900):
            return entry["data"]
    return None


def _cache_set(source, data):
    """Store intel in cache."""
    with _lock:
        _intel_cache[source] = {"data": data, "ts": time.time()}


# ═══════════════════════════════════════════
# Fetchers
# ═══════════════════════════════════════════

def fetch_abuseipdb():
    """
    Fetch recent reported IPs from AbuseIPDB (requires API key).
    Returns list of {ip, abuse_score, categories, country, last_reported}.
    Falls back to cached data if available.
    """
    if not ABUSEIPDB_KEY:
        _log("AbuseIPDB: no API key configured, skipping")
        return _cache_get("abuseipdb") or []

    cached = _cache_get("abuseipdb")
    if cached:
        return cached

    url = "https://api.abuseipdb.com/api/v2/blacklist"
    headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
    params = "?confidenceMinimum=90&limit=100"
    data = _fetch_url(url + params, headers=headers)

    if not data or "data" not in data:
        _log("AbuseIPDB: fetch failed or empty, using cache")
        return cached or []

    entries = []
    for item in data.get("data", []):
        entries.append({
            "ip": item.get("ipAddress", ""),
            "score": item.get("abuseConfidenceScore", 0),
            "categories": item.get("categories", []),
            "country": item.get("countryCode", ""),
            "last_reported": item.get("lastReportedAt", ""),
        })
    _cache_set("abuseipdb", entries)
    _log(f"AbuseIPDB: loaded {len(entries)} entries")
    return entries


def fetch_otx():
    """
    Fetch AlienVault OTX pulses (community threat indicators).
    Uses public API endpoint — no key required for community pulses.
    Returns list of {ip, indicators_count, title}.
    """
    cached = _cache_get("otx")
    if cached:
        return cached

    # Use the public pulse feed — no API key needed
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
    headers = {"X-OTX-API-KEY": OTX_KEY} if OTX_KEY else {}
    data = _fetch_url(url, headers=headers)

    if not data or "results" not in data:
        _log("OTX: fetch failed or empty, using cache")
        return cached or []

    entries = []
    for pulse in data.get("results", []):
        indicators = pulse.get("indicators", [])
        ips = [i.get("indicator") for i in indicators
               if i.get("type") in ("IPv4", "IPv6")]
        for ip in ips:
            entries.append({
                "ip": ip,
                "title": pulse.get("name", ""),
                "pulse_id": pulse.get("id", ""),
                "created": pulse.get("created", ""),
            })
    _cache_set("otx", entries)
    _log(f"OTX: loaded {len(entries)} IP indicators")
    return entries


def fetch_urlhaus():
    """
    Fetch recent malicious URLs from URLhaus (abuse.ch).
    Public API, no key required.
    Returns list of {url, host, ip, threat, malware_family}.
    """
    cached = _cache_get("urlhaus")
    if cached:
        return cached

    url = "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/100/"
    data = _fetch_url(url)

    if not data or "urls" not in data:
        _log("URLhaus: fetch failed, using cache")
        return cached or []

    entries = []
    for item in data.get("urls", []):
        url_str = item.get("url", "")
        try:
            host = item.get("host", "")
            ip = socket.gethostbyname(host) if host else ""
        except Exception:
            ip = ""
        entries.append({
            "url": url_str,
            "host": host,
            "ip": ip,
            "threat": item.get("threat", ""),
            "malware_family": item.get("urlhaus_references", [{}])[0].get("malware", "") if item.get("urlhaus_references") else "",
            "date_added": item.get("date_added", ""),
        })
    _cache_set("urlhaus", entries)
    _log(f"URLhaus: loaded {len(entries)} entries")
    return entries


def fetch_feodo():
    """
    Fetch Feodo Tracker C2 blocklist (abuse.ch).
    Public CSV, no key required.
    Returns list of {ip, malware, status, last_seen}.
    """
    cached = _cache_get("feodo")
    if cached:
        return cached

    # Feodo IP blocklist (recommended)
    url = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"
    text = _fetch_url(url)

    if not text or isinstance(text, dict):
        _log("Feodo: fetch failed, using cache")
        return cached or []

    entries = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Format: ip_address  # malware_family  (tab or space separated)
        parts = line.split()
        if len(parts) >= 1:
            ip = parts[0]
            if not _is_ip(ip):
                continue
            malware = " ".join(parts[1:]).lstrip("#").strip() if len(parts) > 1 else "unknown"
            entries.append({
                "ip": ip,
                "malware": malware,
                "status": "active",
                "source": "feodo",
            })
    _cache_set("feodo", entries)
    _log(f"Feodo: loaded {len(entries)} C2 IPs")
    return entries


def fetch_tor_exits():
    """
    Fetch Tor exit node list from Tor Project.
    Public list, no key required.
    Returns list of {ip, fingerprint}.
    """
    cached = _cache_get("tor")
    if cached:
        return cached

    url = "https://check.torproject.org/torbulkexitlist"
    text = _fetch_url(url)

    if not text or isinstance(text, dict):
        _log("Tor: fetch failed, using cache")
        return cached or []

    entries = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if _is_ip(line):
            entries.append({"ip": line, "source": "tor_exit"})
    _cache_set("tor", entries)
    _log(f"Tor: loaded {len(entries)} exit nodes")
    return entries


def _is_ip(s):
    """Check if string is a valid IPv4 address."""
    parts = s.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except (ValueError, TypeError):
        return False


# ═══════════════════════════════════════════
# Observed IP/Domain Tracking
# ═══════════════════════════════════════════

def record_observed_ip(ip, host="", port=None, protocol=""):
    """Record an IP observed in network traffic for later cross-referencing."""
    if not ip or ip.startswith("127.") or ip.startswith("10.") or ip.startswith("192.168."):
        return  # skip private/local IPs
    with _lock:
        _observed_ips[ip] = {
            "last_seen": time.time(),
            "host": host,
            "port": port,
            "protocol": protocol,
        }


def record_observed_domain(domain, host="", resolved_ip=""):
    """Record a domain observed in traffic for later cross-referencing."""
    if not domain:
        return
    with _lock:
        _observed_domains[domain] = {
            "last_seen": time.time(),
            "host": host,
            "resolved_ip": resolved_ip,
        }


def get_observed_ips():
    """Get all observed IPs (for cross-reference)."""
    with _lock:
        return dict(_observed_ips)


def get_observed_domains():
    """Get all observed domains (for cross-reference)."""
    with _lock:
        return dict(_observed_domains)


# ═══════════════════════════════════════════
# Cross-Reference Engine
# ═══════════════════════════════════════════

# Will be imported at runtime to avoid circular import
_create_alert = None


def _check_ip_against_intel(ip, ip_meta, source_name, intel_data):
    """
    Check a single observed IP against a source's intel data.
    Returns alert dicts for matches.
    """
    global _create_alert
    if _create_alert is None:
        try:
            from detection import create_alert as ca
            _create_alert = ca
        except ImportError:
            return []

    alerts = []
    for entry in intel_data:
        if entry.get("ip") != ip:
            continue

        severity = THREAT_SEVERITY.get(source_name, "medium")
        title = f"Threat intel match: {ip} flagged by {source_name}"
        desc_parts = [f"Observed IP {ip} appears in {source_name} threat intel."]

        if source_name == "abuseipdb":
            score = entry.get("score", 0)
            cats = entry.get("categories", [])
            desc_parts.append(f"Abuse confidence: {score}%")
            if cats:
                desc_parts.append(f"Categories: {', '.join(map(str, cats))}")
        elif source_name == "otx":
            desc_parts.append(f"Pulse: {entry.get('title', 'unknown')}")
        elif source_name == "urlhaus":
            desc_parts.append(f"URL: {entry.get('url', '')}")
            desc_parts.append(f"Threat: {entry.get('threat', 'unknown')}")
            severity = "critical"
        elif source_name == "feodo":
            desc_parts.append(f"Malware: {entry.get('malware', 'unknown')}")
            desc_parts.append("C2 server — immediate investigation required")
            severity = "critical"
        elif source_name == "tor":
            desc_parts.append("Tor exit node — traffic may be anonymized")
            severity = "medium"

        if ip_meta.get("port"):
            desc_parts.append(f"Destination port: {ip_meta['port']}")

        alert = _create_alert(
            severity=severity,
            category="threat_intel",
            title=title,
            description="\n".join(desc_parts),
            source_ip=ip,
            mitre_tactic="Command and Control",
            mitre_technique="T1071 (Application Layer Protocol)",
            raw_data={
                "source": source_name,
                "entry": entry,
                "observed_meta": ip_meta,
            },
        )
        if alert:
            alerts.append(alert)

    return alerts


def cross_reference():
    """
    Cross-reference all observed IPs against current threat intel caches.
    Returns list of alerts generated.
    """
    all_alerts = []
    observed = get_observed_ips()
    if not observed:
        return []

    sources = {
        "abuseipdb": _cache_get("abuseipdb") or [],
        "otx": _cache_get("otx") or [],
        "urlhaus": _cache_get("urlhaus") or [],
        "feodo": _cache_get("feodo") or [],
        "tor": _cache_get("tor") or [],
    }

    for ip, meta in observed.items():
        for source_name, intel_data in sources.items():
            if not intel_data:
                continue
            alerts = _check_ip_against_intel(ip, meta, source_name, intel_data)
            all_alerts.extend(alerts)

    if all_alerts:
        _log(f"Cross-reference: {len(all_alerts)} threat intel matches detected")
    return all_alerts


def get_threat_intel_status():
    """Return status of all threat intel sources for frontend display."""
    status = {}
    for source in CACHE_TTL:
        entry = _intel_cache.get(source)
        if entry:
            age = time.time() - entry["ts"]
            data = entry["data"]
            count = len(data) if isinstance(data, list) else 0
            status[source] = {
                "loaded": True,
                "count": count,
                "age_seconds": round(age),
                "stale": age > CACHE_TTL.get(source, 900),
            }
        else:
            status[source] = {
                "loaded": False,
                "count": 0,
                "age_seconds": 0,
                "stale": True,
            }
    status["observed_ips"] = len(get_observed_ips())
    status["observed_domains"] = len(get_observed_domains())
    return status


# ═══════════════════════════════════════════
# Background Collectors
# ═══════════════════════════════════════════

def _refresh_source(source_name, fetch_func, interval):
    """Background loop that periodically refreshes a single source."""
    while _collector_running:
        try:
            _log(f"Refreshing {source_name}...")
            data = fetch_func()
            if data:
                _log(f"{source_name}: refreshed ({len(data) if isinstance(data, list) else 'ok'})")
        except Exception as e:
            _log(f"{source_name} refresh error: {e}")
        time.sleep(interval)


def _cross_reference_loop():
    """Background loop that cross-references observed IPs against threat intel."""
    while _collector_running:
        try:
            alerts = cross_reference()
            if alerts:
                _log(f"Cross-reference generated {len(alerts)} alerts")
        except Exception as e:
            _log(f"Cross-reference error: {e}")
        time.sleep(INTERVAL_CROSS_REFERENCE)


def start_collector():
    """Start all threat intel background threads."""
    global _collector_running
    if _collector_running:
        _log("Threat intel collector already running")
        return

    _collector_running = True
    _log("═══ Threat Intel Engine Starting ═══")
    _log(f"AbuseIPDB: {'configured' if ABUSEIPDB_KEY else 'not configured (skipping)'}")
    _log(f"OTX: {'configured' if OTX_KEY else 'public mode (no key)'}")

    # Source refreshers
    sources = [
        ("abuseipdb", fetch_abuseipdb, INTERVAL_ABUSEIPDB),
        ("otx", fetch_otx, INTERVAL_OTX),
        ("urlhaus", fetch_urlhaus, INTERVAL_URLHAUS),
        ("feodo", fetch_feodo, INTERVAL_FEODO),
        ("tor", fetch_tor_exits, INTERVAL_TOR),
    ]

    for name, func, interval in sources:
        t = threading.Thread(target=_refresh_source, args=(name, func, interval),
                             name=f"threatintel-{name}", daemon=True)
        t.start()
        _log(f"Started threat intel source: {name}")

    # Cross-reference engine
    t = threading.Thread(target=_cross_reference_loop,
                         name="threatintel-crossref", daemon=True)
    t.start()
    _log("Started cross-reference engine")

    # Initial fetch for public sources (non-blocking)
    def _initial_fetch():
        _log("Running initial threat intel fetch...")
        fetch_urlhaus()
        fetch_feodo()
        fetch_tor_exits()
        if OTX_KEY:
            fetch_otx()
        elif not OTX_KEY:
            # Try OTX public mode
            try:
                fetch_otx()
            except Exception:
                _log("OTX public mode unavailable, skipping")
        if ABUSEIPDB_KEY:
            fetch_abuseipdb()
        _log("Initial threat intel fetch complete")

    t = threading.Thread(target=_initial_fetch, name="threatintel-init", daemon=True)
    t.start()


def stop_collector():
    """Signal all background collectors to stop."""
    global _collector_running
    _collector_running = False
    _log("Threat intel collector stopping")
