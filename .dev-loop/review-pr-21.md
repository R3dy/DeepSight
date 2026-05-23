# PR #21 Review: feat(soar): Automated Enrichment Playbooks

**Branch:** `feature/soar-playbooks` → `main`
**Reviewer:** Operant (automated review agent)
**Tests:** 66/66 passing (3.59s)

---

## Summary

Strong feature with well-structured enrichment engine, clean REST API, and thorough test coverage. The playbook architecture is sound — pure enrichment, no automated remediation, per-alert background threads, good error isolation. However, there is **one blocking bug** (Sigma rule engine silently broken when playbook module is absent) plus several high-severity issues that should be addressed before merge.

---

## 🔴 Blocking Issues

### 1. `detection.py`: Sigma stub functions incorrectly scoped inside playbook `except ImportError`

**File:** `detection.py`, lines 58–67
**Severity:** BLOCKING — silently breaks all Sigma rule evaluation when `playbook_engine.py` is absent

```python
except ImportError:
    HAS_PLAYBOOKS = False

    def _get_playbook_engine():
        return None

    def evaluate_sigma(event):        # <— BUG: orphaned Sigma stubs
        return []

    def get_sigma_engine():           # <— BUG
        return None

    def _update_collector_health(*args, **kwargs):  # <— BUG
        pass
```

**Problem:** When `playbook_engine.py` can't be imported, these three stub functions overwrite the real Sigma imports. Since `HAS_SIGMA` is still `True` (Sigma imported successfully), the guard at line ~1639 passes, but `evaluate_sigma` is now the stub that returns `[]`. All Sigma rule matches are silently dropped.

**Verified reproduction:**
```python
# Sigma imports fine → HAS_SIGMA=True, evaluate_sigma=real
# playbook_engine not found → except block redefines evaluate_sigma=stub
# Result: HAS_SIGMA=True but evaluate_sigma returns []
```

**Fix:** Remove lines 60–67 from the playbook's `except ImportError` block. These stubs already serve no purpose here — the Sigma `except ImportError` block already handles the fallback case with the `HAS_SIGMA` guard. If the intent was to add stubs for the case where Sigma import also fails, they need to go in the Sigma except block (currently empty at lines 49–50).

---

## 🟠 High Severity

### 2. `_enrich_alert` doesn't null-check engine before calling `.process_alert()`

**File:** `detection.py`, line ~1558

```python
engine = _get_playbook_engine()   # returns None if not HAS_PLAYBOOKS
engine.process_alert(alert_dict)  # AttributeError on None
```

The bare `except Exception: pass` catches this, so it won't crash, but it's a wasted exception on every alert when playbooks are unavailable. Add `if engine is None: return`.

### 3. `whois_check` never follows referral — returns IANA root data only

**File:** `playbook_engine.py`, line 564

The function connects to `whois.iana.org` (the IANA root server) which only returns referral information pointing to the TLD-specific whois server. It never parses the `refer:` field and reconnects to get actual domain registration data. The current implementation returns effectively useless whois data.

Either implement referral-following, or use an HTTP whois API (e.g., `whoisxmlapi.com`), or rename/mark this as "whois_referral_check" to set expectations.

### 4. `abuseipdb_check` passes `verbose: ""` as query parameter

**File:** `playbook_engine.py`, line ~236

```python
params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
```

The AbuseIPDB API expects `verbose` to be a boolean or absent. Passing an empty string is non-standard and may cause unexpected behavior depending on API version. Should be `verbose: True` or omitted.

---

## 🟡 Medium Severity

### 5. `tor_exit_check` and `feodo_check` fetch full blocklists on every call

**Files:** `playbook_engine.py`, lines ~320, ~395

Both functions download the entire blocklist from the respective services on every enrichment run, even if checking a single IP. For a busy pipeline (e.g., brute-force storms generating many alerts), this will:
- Hammer the upstream services (risk of rate-limiting/IP bans)
- Add significant latency to every enrichment run (network round-trip to download bulk data)

**Fix:** Add a TTL-based cache for the blocklists (e.g., refresh every 15 minutes with a background thread).

### 6. `_append_enrichment_to_alert` catches all exceptions silently

**File:** `playbook_engine.py`, line ~550

```python
except Exception as e:
    _log(f"Alert {alert_id}: failed to append enrichment to DB: {e}")
```

Broad exception catches include `OperationalError` (DB locked), `InterfaceError` (connection closed), etc. At minimum, log the full traceback. Consider adding a retry for transient DB errors.

### 7. GeoIP uses plain HTTP to ip-api.com

**File:** `playbook_engine.py`, line ~340

`http://ip-api.com/json/{ip}` — no TLS. IP addresses being enriched are sent in cleartext. ip-api.com supports HTTPS; switch to `https://`.

### 8. `EnrichmentPanel` input sanitization

**File:** `src/components/security/EnrichmentPanel.tsx`

The `manualIp` text input is passed directly to the API without client-side validation. While the server-side handles this safely (no code execution), an invalid input produces a confusing error. Add basic IP/domain format validation on the client.

---

## 🔵 Low / Style

### 9. No pagination controls in `PlaybookHistory` UI

**File:** `src/components/security/PlaybookHistory.tsx`

The API supports `limit`/`offset` pagination but the UI component always fetches with `limit=50, offset=0` and doesn't expose any "Load more" or pagination controls. When history exceeds 50 entries, older runs become invisible.

### 10. Rate limiter never uses cooldown in playbook execution

**File:** `playbook_engine.py`

The `RateLimiter.can_call()` / `record_call()` methods exist but are never called in the engine's `run()` or `process_alert()` paths. The semaphore provides concurrency limiting, but the per-service cooldown logic is dead code during actual playbook execution. Either wire it in or remove it.

### 11. `_EnrichmentFunctions` class is a pure namespace

The class has no state, no `__init__`, and only static methods. This adds unnecessary indirection. Module-level functions would be cleaner, but since `_EnrichmentFunctions` is imported in tests, changing it would require test updates. Low priority, noting for future cleanup.

### 12. `json.dumps` on enrichment data could fail

**File:** `playbook_engine.py`, line ~580

```python
enrichment_json = json.dumps(enrichment_data)
```

If any enrichment function returns a non-serializable object (e.g., `datetime`, `bytes`, `set`), this will raise `TypeError` and be silently caught by the broad except. Add a `default=str` fallback.

### 13. `get_results` casts alert_id to `int()` — no None guard

**File:** `playbook_engine.py`, line ~505

```python
return self._results.get(int(alert_id))
```

If `alert_id` is `None` (e.g., from a manual enrichment without an alert_id), this raises `ValueError`. Add a `None` check.

---

## ✅ What's Good

- **Architecture:** Clean separation — engine, steps, playbooks, API routes, React components all well-decoupled.
- **Error isolation:** Each step runs independently; one enrichment failure never blocks others.
- **Test coverage:** 66 tests covering rate limiting, context extraction, IP validation, whois parsing, all enrichment functions (mocked), integration with alert pipeline, and the singleton pattern. All passing.
- **RBAC:** `require_permission("cases:write")` on the `/playbooks/run` endpoint — correct permission choice.
- **Non-blocking:** `process_alert` returns immediately; enrichment runs in a daemon thread. Won't slow down alert creation.
- **Fallback patterns:** Both `detection.py` and `routes/v2/playbooks.py` gracefully degrade when playbook_engine isn't available.
- **API audit logging:** All playbook routes log via `log_api_audit`, consistent with existing v2 routes.
- **Frontend design:** Clean Obsidian Arcane styling, loading skeletons, expandable step details, manual trigger with playbook selector.

---

## Verdict

**❌ REQUEST CHANGES** — The Sigma stub scoping bug (Issue #1) is a blocker that silently breaks an existing feature. Fix that, and address the high-severity items (especially #3 whois referrals and #2 null check). The medium items are worthwhile improvements but not blockers for merge.
