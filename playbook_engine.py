#!/usr/bin/env python3
"""
DeepSight SOAR Playbook Engine — Automated Enrichment for Security Alerts.

Pure enrichment only — NO automated remediation. Each playbook defines:
  1. A trigger condition (which alert types fire it)
  2. Ordered enrichment steps
  3. A results dictionary appended to the alert as the `enrichment` field.

Enrichment runs non-blocking after alert creation via background threads.
"""

import json
import os
import re
import time
import socket
import threading
import ipaddress
from collections import defaultdict
from datetime import datetime, timezone

import requests

# ═══════════════════════════════════════════
# Configuration (env vars / config file)
# ═══════════════════════════════════════════

ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
OTX_API_KEY = os.environ.get("OTX_API_KEY", "")
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
URLHAUS_API_URL = "https://urlhaus-api.abuse.ch/v1/"
FEODO_API_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"

# Rate limiting
MAX_CONCURRENT_API_CALLS = int(os.environ.get("PLAYBOOK_MAX_CONCURRENT", 3))
DEFAULT_COOLDOWN_SECONDS = 60  # per-service cooldown
IP_COOLDOWN_SECONDS = int(os.environ.get("PLAYBOOK_IP_COOLDOWN", 60))
DOMAIN_COOLDOWN_SECONDS = int(os.environ.get("PLAYBOOK_DOMAIN_COOLDOWN", 60))
HASH_COOLDOWN_SECONDS = int(os.environ.get("PLAYBOOK_HASH_COOLDOWN", 60))

# Request timeouts
REQUEST_TIMEOUT = int(os.environ.get("PLAYBOOK_REQUEST_TIMEOUT", 10))

# Enable/disable individual enrichment modules
ENABLE_ABUSEIPDB = os.environ.get("ENABLE_ABUSEIPDB", "1") == "1"
ENABLE_OTX = os.environ.get("ENABLE_OTX", "1") == "1"
ENABLE_TOR_CHECK = os.environ.get("ENABLE_TOR_CHECK", "1") == "1"
ENABLE_GEOIP = os.environ.get("ENABLE_GEOIP", "1") == "1"
ENABLE_URLHAUS = os.environ.get("ENABLE_URLHAUS", "1") == "1"
ENABLE_FEODO = os.environ.get("ENABLE_FEODO", "1") == "1"
ENABLE_WHOIS = os.environ.get("ENABLE_WHOIS", "1") == "1"
ENABLE_VIRUSTOTAL = os.environ.get("ENABLE_VIRUSTOTAL", "1") == "1"
ENABLE_DNS_ENRICHMENT = os.environ.get("ENABLE_DNS_ENRICHMENT", "1") == "1"


# ═══════════════════════════════════════════
# Logging
# ═══════════════════════════════════════════

def _log(msg):
    """Timestamped log to stdout."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[playbook {ts}] {msg}", flush=True)


# ═══════════════════════════════════════════
# Rate Limiter
# ═══════════════════════════════════════════

class RateLimiter:
    """Per-service cooldown tracker with max concurrent limit."""

    def __init__(self, max_concurrent=MAX_CONCURRENT_API_CALLS):
        self._cooldowns = {}       # service_name -> last_call_timestamp
        self._semaphore = threading.BoundedSemaphore(max_concurrent)

    def can_call(self, service_name, cooldown_seconds=DEFAULT_COOLDOWN_SECONDS):
        """Check if a service is outside its cooldown window."""
        now = time.time()
        last = self._cooldowns.get(service_name, 0)
        if now - last < cooldown_seconds:
            return False
        return True

    def record_call(self, service_name):
        """Record that a service was called now."""
        self._cooldowns[service_name] = time.time()

    def acquire(self):
        """Acquire the concurrency semaphore (blocking)."""
        self._semaphore.acquire()

    def release(self):
        """Release the concurrency semaphore."""
        self._semaphore.release()


# ═══════════════════════════════════════════
# Playbook Step Definition
# ═══════════════════════════════════════════

class PlaybookStep:
    """A single enrichment step within a playbook."""

    def __init__(self, name, func, timeout=REQUEST_TIMEOUT):
        self.name = name
        self.func = func          # callable(context) -> dict result
        self.timeout = timeout

    def run(self, context):
        """Run this step with timeout and error handling."""
        result = {
            "name": self.name,
            "status": "pending",
            "data": None,
            "error": None,
            "duration_ms": 0,
        }
        start = time.time()
        try:
            data = self.func(context)
            result["status"] = "success"
            result["data"] = data
        except requests.Timeout:
            result["status"] = "error"
            result["error"] = f"Timeout after {self.timeout}s"
        except requests.ConnectionError:
            result["status"] = "error"
            result["error"] = "Connection failed (offline?)"
        except Exception as e:
            result["status"] = "error"
            result["error"] = f"{type(e).__name__}: {str(e)[:200]}"
        finally:
            result["duration_ms"] = round((time.time() - start) * 1000)
        return result


# ═══════════════════════════════════════════
# Playbook Definition
# ═══════════════════════════════════════════

class Playbook:
    """A named playbook with trigger condition and ordered enrichment steps."""

    def __init__(self, name, description, trigger_condition, steps):
        self.name = name
        self.description = description
        self.trigger_condition = trigger_condition  # callable(alert_dict) -> bool
        self.steps = steps  # list of PlaybookStep

    def matches(self, alert_dict):
        """Check if this playbook should fire for an alert."""
        try:
            return self.trigger_condition(alert_dict)
        except Exception:
            return False

    def run(self, alert_dict, rate_limiter):
        """Execute all steps sequentially, return enrichment results."""
        results = {
            "playbook": self.name,
            "alert_id": alert_dict.get("id"),
            "started_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "status": "running",
            "steps": [],
            "error": None,
        }

        # Build context from alert data
        context = _build_enrichment_context(alert_dict)

        for step in self.steps:
            rate_limiter.acquire()
            try:
                step_result = step.run(context)
                results["steps"].append(step_result)
            finally:
                rate_limiter.release()

        # Determine overall status
        errors = [s for s in results["steps"] if s["status"] == "error"]
        if errors and len(errors) == len(results["steps"]):
            results["status"] = "error"
            results["error"] = "All enrichment steps failed"
        elif errors:
            results["status"] = "partial"
        else:
            results["status"] = "success"

        results["completed_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        return results


# ═══════════════════════════════════════════
# Enrichment Context Builder
# ═══════════════════════════════════════════

def _build_enrichment_context(alert_dict):
    """Build an enrichment context dict from an alert.

    Extracts IPs, domains, file hashes from alert fields.
    """
    context = {
        "alert_id": alert_dict.get("id"),
        "category": alert_dict.get("category", ""),
        "severity": alert_dict.get("severity", ""),
        "title": alert_dict.get("title", ""),
        "description": alert_dict.get("description", ""),
        "source_ip": alert_dict.get("source_ip", ""),
        "source_host": alert_dict.get("source_host", ""),
        "ips": [],
        "domains": [],
        "hashes": [],
    }

    # Extract IPs from alert fields
    if alert_dict.get("source_ip"):
        addr = alert_dict["source_ip"].strip()
        if _is_valid_ip(addr):
            context["ips"].append(addr)

    # Extract IPs from raw_data
    raw = alert_dict.get("raw_data") or {}
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            raw = {}

    for field in ("remote_ip", "source_ip", "dst_ip", "ip"):
        val = raw.get(field, "")
        if val and _is_valid_ip(val) and val not in context["ips"]:
            context["ips"].append(val)

    # Also scan description and title for IPs
    ip_pattern = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
    for text in [alert_dict.get("description", ""), alert_dict.get("title", "")]:
        for match in ip_pattern.finditer(text):
            ip = match.group(1)
            if _is_valid_ip(ip) and ip not in context["ips"]:
                context["ips"].append(ip)

    # Extract domains from alert fields
    raw_domains = []
    if alert_dict.get("source_host") and "." in alert_dict["source_host"]:
        raw_domains.append(alert_dict["source_host"])

    for field in ("remote_host", "tls_sni", "domain", "host"):
        val = raw.get(field, "")
        if val and "." in str(val):
            raw_domains.append(str(val))

    # Domain regex pattern
    domain_pattern = re.compile(
        r'\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,})\b'
    )
    for text in [alert_dict.get("description", ""), alert_dict.get("title", "")]:
        for match in domain_pattern.finditer(text):
            dom = match.group(1).lower().rstrip(".")
            if dom not in raw_domains:
                raw_domains.append(dom)

    # Deduplicate and validate domains
    seen = set()
    for dom in raw_domains:
        dom = dom.lower().strip()
        if dom and "." in dom and dom not in seen:
            # Skip IPs that match domain pattern
            if not _is_valid_ip(dom):
                seen.add(dom)
                context["domains"].append(dom)

    # Extract file hashes
    hash_pattern = re.compile(r'\b([a-fA-F0-9]{32,64})\b')
    for text in [alert_dict.get("description", ""), alert_dict.get("title", "")]:
        for match in hash_pattern.finditer(text):
            h = match.group(1).lower()
            if h not in context["hashes"]:
                context["hashes"].append(h)

    for field in ("md5", "sha1", "sha256", "hash", "file_hash"):
        val = raw.get(field, "")
        if val and len(str(val)) >= 32:
            h = str(val).lower()
            if h not in context["hashes"]:
                context["hashes"].append(h)

    return context


def _is_valid_ip(addr):
    """Check if a string is a valid (non-private, non-loopback, non-multicast) IPv4/v6."""
    try:
        ip = ipaddress.ip_address(addr.strip())
        if ip.is_loopback or ip.is_multicast or ip.is_unspecified:
            return False
        if ip.is_private:
            return False  # don't waste API calls on private IPs
        return True
    except ValueError:
        return False


# ═══════════════════════════════════════════
# Enrichment Step Functions
# ═══════════════════════════════════════════

class _EnrichmentFunctions:
    """Container for all enrichment step functions (avoids global namespace pollution)."""

    # ─── IP Enrichment ─────────────────────────────────────────

    @staticmethod
    def abuseipdb_check(context):
        """Check IP reputation via AbuseIPDB API v2."""
        if not ABUSEIPDB_API_KEY:
            return {"skipped": True, "reason": "ABUSEIPDB_API_KEY not configured"}
        ips = context.get("ips", [])
        if not ips:
            return {"skipped": True, "reason": "No IPs to check"}

        results = {}
        for ip in ips[:3]:  # limit to 3 IPs per call
            try:
                resp = requests.get(
                    "https://api.abuseipdb.org/api/v2/check",
                    headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
                    params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
                    timeout=REQUEST_TIMEOUT,
                )
                if resp.status_code == 200:
                    data = resp.json()["data"]
                    results[ip] = {
                        "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                        "total_reports": data.get("totalReports", 0),
                        "last_reported_at": data.get("lastReportedAt"),
                        "country": data.get("countryCode"),
                        "isp": data.get("isp"),
                        "domain": data.get("domain"),
                        "usage_type": data.get("usageType"),
                    }
                elif resp.status_code == 429:
                    results[ip] = {"error": "Rate limited by AbuseIPDB"}
                else:
                    results[ip] = {"error": f"HTTP {resp.status_code}"}
            except Exception as e:
                results[ip] = {"error": str(e)[:200]}

        return {"ips": results}

    @staticmethod
    def otx_check(context):
        """Check IP/domain reputation via AlienVault OTX."""
        if not OTX_API_KEY:
            return {"skipped": True, "reason": "OTX_API_KEY not configured"}

        ips = context.get("ips", [])
        domains = context.get("domains", [])
        targets = ips[:2] + domains[:2]  # limit to 4 total

        if not targets:
            return {"skipped": True, "reason": "No IPs or domains to check"}

        results = {}
        for target in targets:
            # Determine if IP or domain
            indicator_type = "IPv4" if _is_valid_ip(target) else "domain"
            try:
                resp = requests.get(
                    f"https://otx.alienvault.com/api/v1/indicators/{indicator_type}/{target}/general",
                    headers={"X-OTX-API-KEY": OTX_API_KEY},
                    timeout=REQUEST_TIMEOUT,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    results[target] = {
                        "pulse_count": data.get("pulse_info", {}).get("count", 0),
                        "pulses": [
                            {"name": p.get("name"), "created": p.get("created")}
                            for p in data.get("pulse_info", {}).get("pulses", [])[:3]
                        ],
                        "type_title": data.get("type_title", indicator_type),
                        "validation": data.get("validation", []),
                    }
                else:
                    results[target] = {"error": f"HTTP {resp.status_code}"}
            except Exception as e:
                results[target] = {"error": str(e)[:200]}

        return {"indicators": results}

    @staticmethod
    def tor_exit_check(context):
        """Check if IP is a Tor exit node using Tor Project bulk list."""
        ips = context.get("ips", [])
        if not ips:
            return {"skipped": True, "reason": "No IPs to check"}

        # Fetch Tor exit node list
        tor_exits = set()
        try:
            resp = requests.get(
                "https://check.torproject.org/torbulkexitlist",
                timeout=REQUEST_TIMEOUT,
            )
            if resp.status_code == 200:
                for line in resp.text.strip().split("\n"):
                    line = line.strip()
                    if line and not line.startswith("#"):
                        tor_exits.add(line)
        except Exception:
            return {"error": "Failed to fetch Tor exit node list", "results": {}}

        results = {}
        for ip in ips:
            results[ip] = {
                "is_tor_exit": ip in tor_exits,
            }

        return {"results": results}

    @staticmethod
    def geoip_check(context):
        """GeoIP lookup using ip-api.com (free, no key required)."""
        ips = context.get("ips", [])
        if not ips:
            return {"skipped": True, "reason": "No IPs to check"}

        results = {}
        for ip in ips[:5]:  # ip-api.com free tier limits
            try:
                resp = requests.get(
                    f"http://ip-api.com/json/{ip}",
                    params={"fields": "country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as"},
                    timeout=REQUEST_TIMEOUT,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("status") == "success":
                        results[ip] = {
                            "country": data.get("country"),
                            "country_code": data.get("countryCode"),
                            "region": data.get("regionName"),
                            "city": data.get("city"),
                            "timezone": data.get("timezone"),
                            "isp": data.get("isp"),
                            "org": data.get("org"),
                            "as": data.get("as"),
                            "coordinates": {
                                "lat": data.get("lat"),
                                "lon": data.get("lon"),
                            },
                        }
                    else:
                        results[ip] = {"error": data.get("message", "Unknown error")}
                else:
                    results[ip] = {"error": f"HTTP {resp.status_code}"}
            except Exception as e:
                results[ip] = {"error": str(e)[:200]}

        return {"ips": results}

    # ─── Domain Enrichment ─────────────────────────────────────

    @staticmethod
    def urlhaus_check(context):
        """Check domains/URLs against URLhaus malware URL database."""
        domains = context.get("domains", [])
        if not domains:
            return {"skipped": True, "reason": "No domains to check"}

        results = {}
        for domain in domains[:3]:
            try:
                resp = requests.post(
                    f"{URLHAUS_API_URL}host/",
                    data={"host": domain},
                    timeout=REQUEST_TIMEOUT,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("query_status") == "ok":
                        results[domain] = {
                            "host": data.get("host"),
                            "url_count": data.get("url_count", 0),
                            "urls": [
                                {
                                    "url": u.get("url"),
                                    "threat": u.get("threat"),
                                    "date_added": u.get("date_added"),
                                }
                                for u in data.get("urls", [])[:5]
                            ],
                            "first_seen": data.get("firstseen"),
                        }
                    elif data.get("query_status") == "no_results":
                        results[domain] = {"status": "clean", "url_count": 0}
                    else:
                        results[domain] = {"status": data.get("query_status")}
                else:
                    results[domain] = {"error": f"HTTP {resp.status_code}"}
            except Exception as e:
                results[domain] = {"error": str(e)[:200]}

        return {"domains": results}

    @staticmethod
    def feodo_check(context):
        """Check IPs against Feodo Tracker (C2 server blocklist)."""
        ips = context.get("ips", [])
        if not ips:
            return {"skipped": True, "reason": "No IPs to check"}

        # Fetch Feodo blocklist
        try:
            resp = requests.get(FEODO_API_URL, timeout=REQUEST_TIMEOUT)
            if resp.status_code != 200:
                return {"error": f"HTTP {resp.status_code} fetching Feodo blocklist"}

            blocklist = resp.json()
            # Feodo format: [{"ip_address": "x.x.x.x", "port": 443, "status": "online", ...}, ...]
            blocked_ips = {}
            for entry in blocklist:
                ip = entry.get("ip_address", "")
                if ip:
                    blocked_ips[ip] = {
                        "port": entry.get("port"),
                        "status": entry.get("status", "unknown"),
                        "hostname": entry.get("hostname"),
                        "as_number": entry.get("as_number"),
                        "country": entry.get("country"),
                        "first_seen": entry.get("first_seen"),
                        "last_seen": entry.get("last_seen"),
                        "malware": entry.get("malware", ""),
                    }
        except Exception as e:
            return {"error": str(e)[:200]}

        results = {}
        for ip in ips:
            if ip in blocked_ips:
                results[ip] = {
                    "is_c2": True,
                    **blocked_ips[ip],
                }
            else:
                results[ip] = {"is_c2": False}

        return {"feodo_blocklist_version": "current", "ips": results}

    @staticmethod
    def whois_check(context):
        """Basic whois lookup using socket connections (port 43)."""
        domains = context.get("domains", []) + context.get("ips", [])[:1]
        if not domains:
            return {"skipped": True, "reason": "No domains to check"}

        results = {}
        for target in domains[:3]:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(REQUEST_TIMEOUT)
                s.connect(("whois.iana.org", 43))
                s.send(f"{target}\r\n".encode())
                raw = b""
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    raw += chunk
                s.close()
                response = raw.decode("utf-8", errors="replace")

                # Parse key fields from whois response
                parsed = _parse_whois(response)
                results[target] = parsed
            except socket.timeout:
                results[target] = {"error": "Connection timeout"}
            except Exception as e:
                results[target] = {"error": str(e)[:200]}

        return {"targets": results}

    # ─── File Hash Enrichment ──────────────────────────────────

    @staticmethod
    def virustotal_check(context):
        """Check file hash against VirusTotal API v3."""
        if not VIRUSTOTAL_API_KEY:
            return {"skipped": True, "reason": "VIRUSTOTAL_API_KEY not configured"}

        hashes = context.get("hashes", [])
        if not hashes:
            return {"skipped": True, "reason": "No file hashes to check"}

        results = {}
        for h in hashes[:2]:  # limit API calls
            try:
                resp = requests.get(
                    f"https://www.virustotal.com/api/v3/files/{h}",
                    headers={
                        "x-apikey": VIRUSTOTAL_API_KEY,
                    },
                    timeout=REQUEST_TIMEOUT,
                )
                if resp.status_code == 200:
                    data = resp.json()["data"]
                    attrs = data.get("attributes", {})
                    stats = attrs.get("last_analysis_stats", {})
                    results[h] = {
                        "found": True,
                        "meaningful_name": attrs.get("meaningful_name", ""),
                        "type_description": attrs.get("type_description", ""),
                        "size": attrs.get("size"),
                        "last_analysis_stats": stats,
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "total_engines": sum(stats.values()) if stats else 0,
                    }
                elif resp.status_code == 404:
                    results[h] = {"found": False, "status": "not_in_virustotal"}
                elif resp.status_code == 429:
                    results[h] = {"error": "VirusTotal rate limit exceeded"}
                else:
                    results[h] = {"error": f"HTTP {resp.status_code}"}
            except Exception as e:
                results[h] = {"error": str(e)[:200]}

        return {"hashes": results}

    # ─── DNS Enrichment ────────────────────────────────────────

    @staticmethod
    def reverse_dns_check(context):
        """Reverse DNS (PTR) lookup + forward confirmation for IPs and domains."""
        ips = context.get("ips", [])
        domains = context.get("domains", [])

        results = {}

        # PTR lookup for IPs
        for ip in ips[:5]:
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                # Forward confirmation
                fwd_ips = []
                try:
                    fwd_ips = socket.gethostbyname_ex(hostname)[2]
                except socket.gaierror:
                    pass
                results[ip] = {
                    "ptr": hostname,
                    "forward_confirmed": ip in fwd_ips,
                }
            except (socket.herror, socket.gaierror, socket.timeout):
                results[ip] = {"ptr": None, "forward_confirmed": False}
            except Exception as e:
                results[ip] = {"error": str(e)[:200]}

        # A/AAAA resolution for domains
        for domain in domains[:5]:
            try:
                addrs = socket.getaddrinfo(domain, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
                ipv4 = []
                ipv6 = []
                for addr in addrs:
                    ip = addr[4][0]
                    if ":" in ip:
                        ipv6.append(ip)
                    else:
                        ipv4.append(ip)
                results[domain] = {
                    "resolves": True,
                    "ipv4": list(set(ipv4)),
                    "ipv6": list(set(ipv6)),
                }
            except socket.gaierror:
                results[domain] = {"resolves": False}
            except Exception as e:
                results[domain] = {"error": str(e)[:200]}

        return {"dns": results}


def _parse_whois(raw):
    """Parse significant fields from a raw whois text response."""
    fields = {}
    patterns = {
        "registrar": r"(?i)registrar:\s*(.+)",
        "creation_date": r"(?i)creation\s*date:\s*(.+)",
        "expiration_date": r"(?i)(?:registry\s*)?expir(?:y|ation)\s*date:\s*(.+)",
        "updated_date": r"(?i)updated\s*date:\s*(.+)",
        "name_servers": r"(?i)name\s*server:\s*(.+)",
        "organization": r"(?i)(?:org(?:anization)?):\s*(.+)",
        "country": r"(?i)country:\s*(.+)",
        "status": r"(?i)(?:domain\s*)?status:\s*(.+)",
        "refer": r"(?i)refer:\s*(.+)",
    }
    for key, pattern in patterns.items():
        matches = re.findall(pattern, raw, re.MULTILINE)
        if matches:
            fields[key] = [m.strip() for m in matches] if len(matches) > 1 else matches[0].strip()

    # Also include the raw refer (the real whois server)
    refer_match = re.search(r"(?i)refer:\s*(\S+)", raw)
    if refer_match and "refer" not in fields:
        fields["refer"] = refer_match.group(1).strip()

    return fields


# ═══════════════════════════════════════════
# Playbook Definitions (hardcoded catalog)
# ═══════════════════════════════════════════

def _build_playbook_catalog():
    """Build the catalog of all enrichment playbooks."""
    funcs = _EnrichmentFunctions()

    return [
        Playbook(
            name="ip_enrichment",
            description="Enrich IP addresses with AbuseIPDB, AlienVault OTX, Tor exit node check, and GeoIP",
            trigger_condition=lambda alert: (
                bool(alert.get("source_ip"))
                or alert.get("category") in ("brute_force", "beaconing", "network")
            ),
            steps=[
                PlaybookStep("abuseipdb", funcs.abuseipdb_check),
                PlaybookStep("alienvault_otx", funcs.otx_check),
                PlaybookStep("tor_exit_check", funcs.tor_exit_check),
                PlaybookStep("geoip", funcs.geoip_check),
                PlaybookStep("feodo_tracker", funcs.feodo_check),
            ],
        ),
        Playbook(
            name="domain_enrichment",
            description="Enrich domains with URLhaus, Feodo, and whois",
            trigger_condition=lambda alert: (
                alert.get("category") in ("dga", "beaconing", "phishing", "dns")
                or ".com" in (alert.get("description", "") + alert.get("title", ""))
            ),
            steps=[
                PlaybookStep("urlhaus", funcs.urlhaus_check),
                PlaybookStep("feodo_tracker", funcs.feodo_check),
                PlaybookStep("whois", funcs.whois_check),
            ],
        ),
        Playbook(
            name="file_hash_enrichment",
            description="Look up file hashes via VirusTotal",
            trigger_condition=lambda alert: (
                alert.get("category") in ("malware", "file_integrity", "suspicious_execution")
                or bool(re.search(r'\b[a-fA-F0-9]{32,64}\b',
                                   alert.get("description", "") + alert.get("title", "")))
            ),
            steps=[
                PlaybookStep("virustotal_hash", funcs.virustotal_check),
            ],
        ),
        Playbook(
            name="dns_enrichment",
            description="Reverse DNS (PTR) + forward confirmation for IPs and domains",
            trigger_condition=lambda alert: (
                alert.get("category") in ("dga", "dns", "beaconing", "network")
                or bool(alert.get("source_host"))
            ),
            steps=[
                PlaybookStep("reverse_dns", funcs.reverse_dns_check),
            ],
        ),
    ]


# ═══════════════════════════════════════════
# Playbook Engine
# ═══════════════════════════════════════════

class PlaybookEngine:
    """Orchestrates enrichment playbooks triggered by alerts.

    Usage:
        engine = PlaybookEngine()
        engine.start()  # optionally starts background worker
        engine.process_alert(alert_dict)  # non-blocking enrichment
    """

    def __init__(self):
        self._playbooks = _build_playbook_catalog()
        self._rate_limiter = RateLimiter()
        self._results = {}       # alert_id -> enrichment results
        self._results_lock = threading.Lock()
        self._history = []       # list of recent run summaries (for /history)
        self._history_lock = threading.Lock()
        self._max_history = 200
        self._running = False
        self._worker_thread = None

    @property
    def playbooks(self):
        """Return the list of configured playbooks."""
        return [{"name": p.name, "description": p.description} for p in self._playbooks]

    def start(self):
        """Start background worker thread for queue processing."""
        if self._running:
            return
        self._running = True
        self._worker_thread = threading.Thread(
            target=self._worker_loop, daemon=True, name="playbook-worker"
        )
        self._worker_thread.start()
        _log("PlaybookEngine started")

    def stop(self):
        """Stop the background worker thread."""
        self._running = False
        if self._worker_thread:
            self._worker_thread.join(timeout=5)
        _log("PlaybookEngine stopped")

    def process_alert(self, alert_dict):
        """Process an alert through matching playbooks (fire-and-forget).

        Called by the alert pipeline after alert creation. Non-blocking —
        enrichment runs in the background.
        """
        # Find matching playbooks
        matching = []
        for playbook in self._playbooks:
            if playbook.matches(alert_dict):
                matching.append(playbook)

        if not matching:
            return

        _log(f"Alert {alert_dict.get('id')}: matched {len(matching)} playbook(s) — "
             f"{[p.name for p in matching]}")

        # Run enrichment in background thread
        t = threading.Thread(
            target=self._run_enrichment,
            args=(alert_dict, matching),
            daemon=True,
            name=f"pb-{alert_dict.get('id', 'unknown')}",
        )
        t.start()

    def _run_enrichment(self, alert_dict, playbooks):
        """Execute matching playbooks and store results."""
        alert_id = alert_dict.get("id")
        combined_results = {
            "alert_id": alert_id,
            "enriched_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "playbook_results": [],
        }

        for playbook in playbooks:
            try:
                result = playbook.run(alert_dict, self._rate_limiter)
                combined_results["playbook_results"].append(result)
            except Exception as e:
                _log(f"Playbook {playbook.name} crashed: {e}")
                combined_results["playbook_results"].append({
                    "playbook": playbook.name,
                    "status": "error",
                    "error": str(e),
                })

        # Store results
        with self._results_lock:
            self._results[alert_id] = combined_results

        # Add to history
        history_entry = {
            "alert_id": alert_id,
            "timestamp": combined_results["enriched_at"],
            "playbooks_run": [
                {
                    "name": r["playbook"],
                    "status": r["status"],
                }
                for r in combined_results["playbook_results"]
            ],
        }
        with self._history_lock:
            self._history.insert(0, history_entry)
            if len(self._history) > self._max_history:
                self._history = self._history[:self._max_history]

        # Append enrichment to the alert in the database
        _append_enrichment_to_alert(alert_id, combined_results)

        _log(f"Alert {alert_id}: enrichment complete — "
             f"{[r['status'] for r in combined_results['playbook_results']]}")

    def _worker_loop(self):
        """Background worker — currently a no-op placeholder.

        The engine uses per-alert threads for enrichment. This loop exists
        for future use (queue-based processing, scheduled re-checks).
        """
        while self._running:
            time.sleep(5)

    def get_results(self, alert_id):
        """Get enrichment results for a specific alert."""
        with self._results_lock:
            return self._results.get(int(alert_id))

    def get_history(self, limit=50, offset=0):
        """Get recent playbook run history (paginated)."""
        with self._history_lock:
            total = len(self._history)
            page = self._history[offset:offset + limit]
            return {
                "history": page,
                "total": total,
                "limit": limit,
                "offset": offset,
            }

    def run_playbook_by_name(self, alert_dict, playbook_name):
        """Manually trigger a specific playbook for an alert.

        Returns the enrichment results dict (synchronously).
        """
        for playbook in self._playbooks:
            if playbook.name == playbook_name:
                result = playbook.run(alert_dict, self._rate_limiter)

                # Store result
                alert_id = alert_dict.get("id")
                combined = {
                    "alert_id": alert_id,
                    "enriched_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "playbook_results": [result],
                }
                with self._results_lock:
                    self._results[alert_id] = combined

                # Add history
                history_entry = {
                    "alert_id": alert_id,
                    "timestamp": combined["enriched_at"],
                    "playbooks_run": [{"name": result["playbook"], "status": result["status"]}],
                }
                with self._history_lock:
                    self._history.insert(0, history_entry)
                    if len(self._history) > self._max_history:
                        self._history = self._history[:self._max_history]

                _append_enrichment_to_alert(alert_id, combined)
                return result

        return {"error": f"Playbook '{playbook_name}' not found"}


# ═══════════════════════════════════════════
# Database Integration — Append to alerts
# ═══════════════════════════════════════════

def _append_enrichment_to_alert(alert_id, enrichment_data):
    """Append enrichment data to an alert in the SQLite database.

    Adds/updates an 'enrichment' column by storing JSON in raw_data.
    If an enrichment column doesn't exist, migrates the schema.
    """
    try:
        from detection import get_db as _get_db
        conn = _get_db()

        # Ensure enrichment column exists (safe migration)
        existing = {row[1] for row in conn.execute("PRAGMA table_info(alerts)")}
        if "enrichment" not in existing:
            conn.execute("ALTER TABLE alerts ADD COLUMN enrichment TEXT DEFAULT ''")
            conn.commit()

        enrichment_json = json.dumps(enrichment_data)
        conn.execute(
            "UPDATE alerts SET enrichment = ? WHERE id = ?",
            (enrichment_json, alert_id),
        )
        conn.commit()
        _log(f"Alert {alert_id}: enrichment appended to database")
    except Exception as e:
        _log(f"Alert {alert_id}: failed to append enrichment to DB: {e}")


# ═══════════════════════════════════════════
# Global singleton
# ═══════════════════════════════════════════

_playbook_engine = None
_engine_lock = threading.Lock()


def get_playbook_engine():
    """Get or create the global PlaybookEngine singleton."""
    global _playbook_engine
    if _playbook_engine is None:
        with _engine_lock:
            if _playbook_engine is None:
                _playbook_engine = PlaybookEngine()
                _playbook_engine.start()
    return _playbook_engine
