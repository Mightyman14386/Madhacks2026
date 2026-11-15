"""Geofence orchestration: preview, block, undo, and state. Endpoints in server.py stay thin.

- firewall.py does the OS work; this module decides and records.
- Blocked state is derived by replaying geofence_log (db.get_blocked_regions()). A region is only
  marked blocked after the firewall step succeeds; undo appends a reverse event, never deletes.
- Responses contain public remote IPs only. Local, gateway, and DNS addresses never leave the server
  (firewall.filter_ips drops them and skipped IPs are reported as counts only).
- Every public function returns (http_status, body) and never raises.
"""
import asyncio
import json
import logging
import math
import threading
import time
from collections import Counter, deque
from datetime import datetime, timedelta, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict

import config
import connections
import db
import events
import firewall
import geo
import geo_ranges

log = logging.getLogger("geotracker.geofence")

_lock = threading.RLock()
# In-memory view of active blocks:
# {cc: {"ips": set, "since": iso, "expires_at": iso, "mode": str, "scope": str, "range_count": int, "rule_names": list}}
_active = {}
_loaded = False

# Background sync bookkeeping (exposed via state()).
_sync = {"last_sync_at": None, "last_sync_ms": None, "errors": deque(maxlen=5)}
_ttl_failure_logged = set()  # regions whose TTL removal failure was already logged (log once, retry every tick)

GEOIP_NOTE = "GeoIP is approximate; sites on shared CDNs in this country may also be affected."
NO_KILL_NOTE = "Existing connections may continue briefly; new connections are blocked."
RESET_NOTE = "Existing connections to these IPs will be reset."
NO_IPS_NOTE = "No real connections to this country right now; the rule will be created when one appears."
VALID_SCOPES = ("observed", "country")

# geo.py has no code -> name lookup, so names come from live GeoIP results first, then this table.
COUNTRY_NAMES = {
    "AE": "United Arab Emirates", "AR": "Argentina", "AU": "Australia", "BD": "Bangladesh", "BR": "Brazil",
    "BY": "Belarus", "CA": "Canada", "CH": "Switzerland", "CL": "Chile", "CN": "China", "CO": "Colombia",
    "CZ": "Czechia", "DE": "Germany", "DK": "Denmark", "EG": "Egypt", "ES": "Spain", "FI": "Finland",
    "FR": "France", "GB": "United Kingdom", "HK": "Hong Kong", "ID": "Indonesia", "IE": "Ireland",
    "IL": "Israel", "IN": "India", "IR": "Iran", "IT": "Italy", "JP": "Japan", "KE": "Kenya",
    "KP": "North Korea", "KR": "South Korea", "MX": "Mexico", "MY": "Malaysia", "NG": "Nigeria",
    "NL": "Netherlands", "NO": "Norway", "NZ": "New Zealand", "PH": "Philippines", "PK": "Pakistan",
    "PL": "Poland", "PT": "Portugal", "RO": "Romania", "RU": "Russia", "SA": "Saudi Arabia", "SE": "Sweden",
    "SG": "Singapore", "TH": "Thailand", "TR": "Turkey", "TW": "Taiwan", "UA": "Ukraine",
    "US": "United States", "VN": "Vietnam", "ZA": "South Africa",
}


class GeofenceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    country_code: str
    confirm: Any = None  # must be exactly JSON true; "true", 1, etc. get the 400 + preview
    scope: str = "observed"


class UndoRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    country_code: str | None = None


# ---------------------------------------------------------------- helpers

def _now():
    return datetime.now(timezone.utc)


def _iso(dt):
    return dt.isoformat(timespec="seconds")


def _expires_at():
    return _iso(_now() + timedelta(minutes=config.RULE_TTL_MINUTES))


def country_name(cc, by_country=None):
    entry = (by_country or {}).get(cc) or {}
    return entry.get("country_name") or COUNTRY_NAMES.get(cc) or cc


def _mode():
    return firewall.enforcement_mode()


def _validate_scope(scope):
    if scope is None:
        return "observed"
    if isinstance(scope, str) and scope in VALID_SCOPES:
        return scope
    return None


def _rule_names_from_row(r):
    cc = r.get("country_code")
    scope = r.get("scope") or "observed"
    rname = r.get("rule_name") or ""
    if scope == "country":
        rcount = int(r.get("range_count") or 0)
        chunk_size = max(1, int(config.FIREWALL_CHUNK_SIZE))
        num_rules = math.ceil(rcount / chunk_size) if rcount > 0 else 0
        return [firewall.chunk_rule_name(cc, i + 1) for i in range(num_rules)]
    return [rname] if rname else ([firewall.rule_name(cc)] if cc else [])


def rebuild_state():
    """Rebuild the in-memory map from the replayed geofence log. Touches no OS state."""
    global _loaded
    with _lock:
        rows = db.get_active_geofences()
        _active.clear()
        for r in rows:
            try:
                ips = set(json.loads(r.get("ips_json") or "[]"))
            except ValueError:
                ips = set()
            scope = r.get("scope") or "observed"
            rcount = r.get("range_count")
            _active[r["country_code"]] = {
                "ips": ips, "since": r.get("ts"), "expires_at": r.get("expires_at"),
                "mode": r.get("mode") or ("enforced" if r.get("enforced") else "dry_run"),
                "scope": scope,
                "range_count": int(rcount) if rcount is not None else (0 if scope == "observed" else 0),
                "rule_names": _rule_names_from_row(r),
            }
        _loaded = True


def _ensure_loaded():
    if not _loaded:
        rebuild_state()


def _blocked():
    return set(db.get_blocked_regions())


def _observed_ips(entry):
    """IPs connected now plus IPs seen in the last 15 minutes for this country."""
    entry = entry or {}
    return set(entry.get("real_ips") or ()) | set(entry.get("recent_ips") or ())


BLOCKED_IPS_SHOWN = 50


def _describe_ips(ips):
    """Blocked public IPs with location/provider and the process that last used them (for the UI)."""
    out = []
    for ip in sorted(ips, key=firewall._sort_key)[:BLOCKED_IPS_SHOWN]:
        g = geo.geolocate(ip) or {}
        out.append({"ip": ip, "city": g.get("city"), "country_code": g.get("country_code"),
                    "asn_org": g.get("asn_org"), "process": connections.recent_process_for(ip)})
    return out


def _reset_to(entry, ips):
    """Reset real TCP connections in `entry` whose remote IP is in `ips`. Returns the count."""
    if not ips:
        return 0
    conns = [c for c in ((entry or {}).get("conns") or []) if c.get("remote_ip") in ips]
    return firewall.reset_tcp_connections(conns) if conns else 0


def _parse_ts(value):
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _sync_error(message):
    _sync["errors"].append(message)
    log.warning("Geofence sync: %s", message)


# ---------------------------------------------------------------- live op events
_op = None  # op currently running under _lock


def _s(step_name, message, status="running", data=None):
    events.step(_op, step_name, message, status, data)


def _finish_op(kind, status, body):
    global _op
    ok = bool(body.get("ok"))
    data = {k: body[k] for k in ("ip_count", "rule_name") if body.get(k) is not None}
    if "reset_connections" in body:
        data["reset_count"] = body["reset_connections"]
    events.end_op(_op, ok, body.get("message"), data or None)
    body["op_id"] = _op
    if ok and _op:
        events.emit_connections_changed(kind)
    _op = None
    return status, body


def _run_op(kind, target, fn, *args):
    global _op
    _op = events.start_op(kind, target)
    try:
        status, body = fn(*args)
    except Exception:
        log.exception("%s failed unexpectedly", kind)
        status, body = 500, {"ok": False, "message": "Unexpected error. See server log."}
    return _finish_op(kind, status, body)


def _sync_event(cc, step_name, message, data=None):
    """A background change (TTL expiry, new IPs, orphan removal) as a one-step 'sync' op."""
    op = events.start_op("sync", {"country_code": cc})
    events.step(op, step_name, message, "ok", data)
    events.end_op(op, True, message, data)
    events.emit_connections_changed("sync")


def _safe(fn, *args):
    try:
        with _lock:
            _ensure_loaded()
            return fn(*args)
    except Exception:
        log.exception("Geofence operation failed")
        return 500, {"ok": False, "message": "Unexpected error. See server log."}


# ---------------------------------------------------------------- preview

def _country_notes(cname):
    return [
        f"Blocks servers located in {cname}, including sites you haven't visited yet.",
        f"Sites on CDNs hosted outside {cname} are not blocked; CDN servers inside {cname} are blocked for every site that uses them.",
        RESET_NOTE if config.RESET_CONNECTIONS_ON_GEOFENCE else NO_KILL_NOTE,
    ]


def _preview_body(code, by_country, scope="observed", range_info=None, ranges_cached=False):
    entry = by_country.get(code) or {}
    cname = country_name(code, by_country)
    allowed, skipped = firewall.filter_ips(_observed_ips(entry))
    mode = _mode()
    if scope == "country" and range_info is not None:
        v4 = range_info.get("v4") or []
        v6 = range_info.get("v6") or []
        all_cidrs = list(v4) + list(v6)
        chunk_size = max(1, int(config.FIREWALL_CHUNK_SIZE))
        rule_count = math.ceil(len(all_cidrs) / chunk_size) if all_cidrs else 0
        command_display = firewall.build_ranges_display(code, all_cidrs) if all_cidrs else None
        return {
            "ok": True,
            "scope": "country",
            "country_code": code,
            "country_name": cname,
            "mode": mode["mode"],
            "mode_reason": mode["reason"],
            "already_blocked": code in _blocked(),
            "ip_count": len(allowed),
            "ips": allowed,
            "skipped_counts": dict(sorted(Counter(s["reason"] for s in skipped).items())),
            "range_count_v4": len(v4),
            "range_count_v6": len(v6),
            "ipv4_address_count": geo_ranges.ipv4_address_count(v4),
            "rule_count": rule_count,
            "ranges_cached": bool(ranges_cached),
            "real_connections_affected": entry.get("real_conn_count", 0),
            "simulated_connections_affected": entry.get("simulated_conn_count", 0),
            "ttl_minutes": config.RULE_TTL_MINUTES,
            "expires_at_if_applied": _expires_at(),
            "command_display": command_display,
            "notes": _country_notes(cname),
        }

    command_display = None
    if allowed:
        command_display = firewall.build_display(code, allowed, update=firewall.rule_exists(code))
    notes = [GEOIP_NOTE, RESET_NOTE if config.RESET_CONNECTIONS_ON_GEOFENCE else NO_KILL_NOTE]
    if not allowed:
        notes.append(NO_IPS_NOTE)
    return {
        "ok": True,
        "scope": "observed",
        "country_code": code,
        "country_name": cname,
        "mode": mode["mode"],
        "mode_reason": mode["reason"],
        "already_blocked": code in _blocked(),
        "ip_count": len(allowed),
        "ips": allowed,  # public, already sorted; private/gateway/DNS never included
        # IPs seen in the last 15 minutes but not connected right now (also blocked)
        "recent_ip_count": len([ip for ip in allowed if ip not in set(entry.get("real_ips") or ())]),
        "skipped_counts": dict(sorted(Counter(s["reason"] for s in skipped).items())),
        "real_connections_affected": entry.get("real_conn_count", 0),
        "simulated_connections_affected": entry.get("simulated_conn_count", 0),
        "ttl_minutes": config.RULE_TTL_MINUTES,
        "expires_at_if_applied": _expires_at(),
        "command_display": command_display,
        "notes": notes,
    }


def _load_country_ranges(code):
    """Return (status, error_body_or_None, range_info, ranges_cached, rule_count)."""
    if geo.geoip_is_fallback and not config.MAXMIND_CITY_PATH.is_file():
        return 400, {"ok": False, "message": "Country-wide geofence is unavailable (MaxMind City database missing)."}, None, False, 0
    try:
        cached = geo_ranges.is_cached(code)
        info = geo_ranges.country_ranges(code)
    except geo_ranges.GeoRangesUnavailableError as e:
        return 400, {"ok": False, "message": str(e)}, None, False, 0
    all_cidrs = list(info.get("v4") or []) + list(info.get("v6") or [])
    if not all_cidrs:
        return 400, {"ok": False, "message": "No public IP ranges found for this country."}, None, cached, 0
    chunk_size = max(1, int(config.FIREWALL_CHUNK_SIZE))
    rule_count = math.ceil(len(all_cidrs) / chunk_size)
    if rule_count > int(config.MAX_COUNTRY_RULES):
        return 400, {"ok": False, "message": "Country too large to block in one step."}, info, cached, rule_count
    return 200, None, info, cached, rule_count


def _preview(country_code, scope="observed", preloaded=None):
    code = firewall.validate_cc(country_code)
    if code is None:
        return 400, {"ok": False, "message": "Invalid country code."}
    sc = _validate_scope(scope)
    if sc is None:
        return 400, {"ok": False, "message": "Invalid scope."}
    if sc == "country":
        status, err, info, cached, _ = preloaded if preloaded is not None else _load_country_ranges(code)
        if status != 200:
            return status, err
        return 200, _preview_body(code, connections.current_ips_by_country(),
                                  scope="country", range_info=info, ranges_cached=cached)
    return 200, _preview_body(code, connections.current_ips_by_country(), scope="observed")


def preview(country_code, scope="observed"):
    return _safe(_preview, country_code, scope)


async def preview_async(country_code, scope="observed"):
    code = firewall.validate_cc(country_code)
    sc = _validate_scope(scope)
    preloaded = None
    if code is not None and sc == "country":
        try:
            preloaded = await asyncio.to_thread(_load_country_ranges, code)
        except Exception:
            log.exception("Async range build failed")
            return 500, {"ok": False, "message": "Unexpected error. See server log."}
    return _safe(_preview, country_code, scope, preloaded)


# ---------------------------------------------------------------- block

def _block(country_code, confirm, scope="observed", preloaded=None):
    code = firewall.validate_cc(country_code)
    if code is None:
        return 400, {"ok": False, "message": "Invalid country code."}
    sc = _validate_scope(scope)
    if sc is None:
        return 400, {"ok": False, "message": "Invalid scope."}

    if code in _blocked():
        existing_scope = (_active.get(code) or {}).get("scope") or "observed"
        if existing_scope != sc:
            return 409, {"ok": False, "message": "Region already geofenced. Undo first."}
        if confirm is True:
            return 409, {"ok": False, "message": "Region already geofenced."}

    range_info = None
    ranges_cached = False
    if sc == "country":
        status, err, range_info, ranges_cached, _ = (
            preloaded if preloaded is not None else _load_country_ranges(code)
        )
        if status != 200:
            return status, err

    by_country = connections.current_ips_by_country()
    if confirm is not True:
        return 400, {
            "ok": False,
            "message": "Confirmation required.",
            "preview": _preview_body(code, by_country, scope=sc,
                                     range_info=range_info, ranges_cached=ranges_cached),
        }
    if code in _blocked():
        return 409, {"ok": False, "message": "Region already geofenced."}

    name = country_name(code, by_country)
    allowed, _ = firewall.filter_ips(_observed_ips(by_country.get(code)))

    if sc == "country":
        all_cidrs = list(range_info.get("v4") or []) + list(range_info.get("v6") or [])
        result = firewall.apply_ranges(code, all_cidrs)
        if not result.get("ok"):
            db.append_audit_event("geofence_failed", "high", f"Geofence failed for {name}", code)
            return 500, {"ok": False, "message": "Firewall rules could not be created."}
        mode = "dry_run" if result.get("dry_run") else "enforced"
        range_count = result.get("range_count", len(all_cidrs))
        rule_names = result.get("rule_names") or []
        apply_ms = result.get("apply_ms", 0)
        expires_at = _expires_at()
        reset = _reset_to(by_country.get(code), set(allowed))
        first_rule = rule_names[0] if rule_names else firewall.rule_name(code)
        db.append_geofence_event(
            "block", code, allowed, first_rule, mode == "enforced",
            result.get("command_display"), None,
            ip_count=len(allowed), mode=mode, expires_at=expires_at, source="user",
            scope="country", range_count=range_count,
        )
        db.append_audit_event(
            "geofence_block", "info",
            f"Geofenced {name} country-wide ({range_count} ranges, {len(rule_names)} rules, {apply_ms} ms)",
            code,
        )
        _active[code] = {
            "ips": set(allowed), "since": _iso(_now()), "expires_at": expires_at,
            "mode": mode, "scope": "country", "range_count": range_count,
            "rule_names": list(rule_names),
        }
        message = f"Geofenced {name} country-wide ({range_count} ranges in {len(rule_names)} rules)."
        if mode == "dry_run":
            message += " Dry run: no firewall rules sent."
        return 200, {
            "ok": True, "message": message, "country_code": code, "country_name": name,
            "scope": "country", "mode": mode, "ip_count": len(allowed),
            "range_count": range_count, "rule_names": rule_names, "apply_ms": apply_ms,
            "expires_at": expires_at, "rule_name": first_rule,
            "command_display": result.get("command_display"), "reset_connections": reset,
        }

    _s("collecting IPs", f"{len(allowed)} public IPs seen for {name}.", "ok", {"ip_count": len(allowed)})
    _s("applying rule", "Sending the firewall rule.", "running", {"rule_name": firewall.rule_name(code)})
    result = firewall.apply_rule(code, allowed)
    if not result.get("ok"):
        db.append_audit_event("geofence_failed", "high", f"Geofence failed for {name}", code)
        _s("applying rule", "Firewall rule could not be created.", "failed")
        return 500, {"ok": False, "message": "Firewall rule could not be created."}
    _s("rule applied", result.get("message"), "ok", {"rule_name": result.get("rule_name")})

    mode = "dry_run" if result.get("dry_run") else "enforced"
    ip_count = result.get("ip_count", len(allowed))
    expires_at = _expires_at()
    _s("resetting connections", "Resetting existing connections to the blocked IPs.")
    reset = _reset_to(by_country.get(code), set(allowed))
    _s("resetting connections", f"{reset} connection(s) reset.", "ok", {"reset_count": reset})
    if mode == "dry_run":
        _s("verified", "Dry run: rule not sent.", "ok")
    elif ip_count == 0:
        _s("verified", "No real IPs yet; the rule will be created when one appears.", "ok")
    else:
        present = firewall.rule_exists(code)
        _s("verified", "Firewall rule is present." if present else "Firewall rule not found after applying.",
           "ok" if present else "failed", {"rule_name": result.get("rule_name")})
    db.append_geofence_event(
        "block", code, allowed, result.get("rule_name"), mode == "enforced",
        result.get("command_display"), None,
        ip_count=ip_count, mode=mode, expires_at=expires_at, source="user",
        scope="observed", range_count=0,
    )  # bumps geofence_version, so the connections cache invalidates
    db.append_audit_event("geofence_block", "info",
                          f"Geofenced {name} ({ip_count} IPs, {mode.replace('_', '-')})", code)
    _active[code] = {
        "ips": set(allowed), "since": _iso(_now()), "expires_at": expires_at,
        "mode": mode, "scope": "observed", "range_count": 0,
        "rule_names": [result.get("rule_name")] if result.get("rule_name") else [firewall.rule_name(code)],
    }

    message = f"Geofenced {name}."
    if ip_count == 0:
        message += " No real IPs yet; rule will be created when one appears."
    elif mode == "dry_run":
        message += " Dry run: no firewall rule sent."
    return 200, {
        "ok": True, "message": message, "country_code": code, "country_name": name, "mode": mode,
        "scope": "observed", "range_count": 0,
        "rule_names": _active[code]["rule_names"],
        "ip_count": ip_count, "expires_at": expires_at, "rule_name": result.get("rule_name"),
        "command_display": result.get("command_display"), "reset_connections": reset,
    }


def _block_op(country_code, confirm, scope="observed", preloaded=None):
    """Run _block as a live op. An op is started only for a confirmed request with a valid code;
    validation/confirmation failures return op_id null."""
    code = firewall.validate_cc(country_code)
    if code is None or confirm is not True or _validate_scope(scope) is None:
        status, body = _block(country_code, confirm, scope, preloaded)
        body["op_id"] = None
        return status, body
    return _run_op("geofence", {"country_code": code}, _block, country_code, confirm, scope, preloaded)


def block(country_code, confirm, scope="observed"):
    return _safe(_block_op, country_code, confirm, scope)


async def block_async(country_code, confirm, scope="observed"):
    code = firewall.validate_cc(country_code)
    sc = _validate_scope(scope)
    preloaded = None
    if code is not None and sc == "country":
        try:
            preloaded = await asyncio.to_thread(_load_country_ranges, code)
        except Exception:
            log.exception("Async range build failed")
            return 500, {"ok": False, "message": "Unexpected error. See server log.", "op_id": None}
    return _safe(_block_op, country_code, confirm, scope, preloaded)


# ---------------------------------------------------------------- undo

def _undo(country_code=None):
    if country_code is None:
        active = db.get_active_geofences()
        if not active:
            return 409, {"ok": False, "message": "No active geofence to undo."}
        code = max(active, key=lambda r: r["id"])["country_code"]  # most recently blocked
    else:
        code = firewall.validate_cc(country_code)
        if code is None:
            return 400, {"ok": False, "message": "Invalid country code."}
        if code not in _blocked():
            return 409, {"ok": False, "message": "Region is not geofenced."}

    name = country_name(code)
    global _op
    _op = events.start_op("undo_geofence", {"country_code": code})
    _s("removing rule", f"Removing the geofence for {name}.")
    result = firewall.remove_rule(code)
    if not result.get("ok"):
        # Stays blocked (no unblock row) so the user can retry.
        db.append_audit_event("geofence_failed", "high", f"Could not remove geofence {name}", code)
        _s("removing rule", "Firewall rule could not be removed.", "failed")
        return 500, {"ok": False, "message": "Firewall rule could not be removed."}
    _s("removing rule", result.get("message"), "ok")

    mode = "dry_run" if result.get("dry_run") else "enforced"
    if mode == "dry_run":
        _s("verified gone", "Dry run: no rule was sent, nothing to remove.", "ok")
    else:
        gone = not firewall.rule_exists(code)
        _s("verified gone", "Firewall rule is gone." if gone else "Firewall rule still present.",
           "ok" if gone else "failed")
    db.append_geofence_event(
        "unblock", code, [], result.get("rule_name"), mode == "enforced",
        result.get("command_display"), None, ip_count=0, mode=mode, source="user",
    )
    db.append_audit_event("geofence_unblock", "info", f"Removed geofence {name}", code)
    _active.pop(code, None)
    return 200, {"ok": True, "message": f"Geofence removed for {name}.", "country_code": code, "mode": mode}


def _undo_op(country_code=None):
    """Run _undo; _undo starts the op itself once the target is known (validation failures: op_id null)."""
    global _op
    _op = None
    try:
        status, body = _undo(country_code)
    except Exception:
        log.exception("Undo failed")
        status, body = 500, {"ok": False, "message": "Unexpected error. See server log."}
    return _finish_op("undo_geofence", status, body)


def undo(country_code=None):
    return _safe(_undo_op, country_code)


# ---------------------------------------------------------------- state

def _state():
    mode = _mode()
    dry = mode["mode"] == "dry_run"
    now = _now()
    rules = firewall.get_rules()  # once per request; [] when not admin
    rule_ccs = {r["country_code"] for r in rules if r.get("country_code")}
    rules_by_cc = {}
    for r in rules:
        rcc = r.get("country_code")
        if rcc:
            rules_by_cc.setdefault(rcc, []).append(r["name"])
    active = db.get_active_geofences()
    active_ccs = {r["country_code"] for r in active}

    blocked = []
    for r in active:
        cc = r["country_code"]
        mem = _active.get(cc) or {}
        scope = mem.get("scope") or r.get("scope") or "observed"
        rcount = mem.get("range_count") if "range_count" in mem else r.get("range_count")
        rnames = mem.get("rule_names") or rules_by_cc.get(cc) or _rule_names_from_row(r)
        expires_at = mem.get("expires_at") or r.get("expires_at")
        exp = _parse_ts(expires_at)
        blocked.append({
            "country_code": cc,
            "country_name": country_name(cc),
            "scope": scope,
            "range_count": int(rcount or 0),
            "rule_names": list(rnames),
            "since": r.get("ts"),
            "expires_at": expires_at,
            "seconds_remaining": None if exp is None else max(0, int((exp - now).total_seconds())),
            # live from the in-memory map (grows as the sync adds new IPs)
            "ip_count": len(mem["ips"]) if "ips" in mem else (r.get("ip_count") or 0),
            "blocked_ips": _describe_ips(mem.get("ips") or ()),
            "mode": r.get("mode") or mem.get("mode") or ("enforced" if r.get("enforced") else "dry_run"),
            "rule_present": None if dry else (cc in rule_ccs),
        })

    orphans = sorted(r["name"] for r in rules if r.get("country_code") not in active_ccs)
    return 200, {
        "ok": True,
        "mode": mode["mode"],
        "mode_reason": mode["reason"],
        "is_admin": firewall.is_admin(),
        "enforce_firewall": config.ENFORCE_FIREWALL,
        "ttl_minutes": config.RULE_TTL_MINUTES,
        "kill_on_geofence": config.KILL_ON_GEOFENCE,
        "reset_connections_enabled": config.RESET_CONNECTIONS_ON_GEOFENCE,
        "sync_seconds": config.GEOFENCE_SYNC_SECONDS,
        "last_sync_at": _sync["last_sync_at"],
        "last_sync_ms": _sync["last_sync_ms"],
        "sync_errors": list(_sync["errors"]),
        "blocked": blocked,
        "orphan_rules": orphans,
        "warnings": firewall.never_block_warnings(),  # plain-English, no IPs
    }


def state():
    return _safe(_state)


# ---------------------------------------------------------------- background sync

def _sync_ttl(now):
    """(a) Expire regions whose TTL passed. Failures stay blocked and retry next tick."""
    for cc, entry in list(_active.items()):
        try:
            exp = _parse_ts(entry.get("expires_at"))
            if exp is None or now < exp:
                continue
            name = country_name(cc)
            result = firewall.remove_rule(cc)
            if not result.get("ok"):
                if cc not in _ttl_failure_logged:
                    _ttl_failure_logged.add(cc)
                    _sync_error(f"Could not remove expired geofence {name}; will retry.")
                continue
            mode = "dry_run" if result.get("dry_run") else "enforced"
            db.append_geofence_event(  # bumps geofence_version
                "unblock", cc, [], result.get("rule_name"), mode == "enforced",
                result.get("command_display"), "TTL expired", ip_count=0, mode=mode, source="ttl",
            )
            db.append_audit_event("geofence_unblock", "info", f"Geofence for {name} expired", cc)
            _sync_event(cc, "ttl expired", f"Geofence for {name} expired")
            _active.pop(cc, None)
            _ttl_failure_logged.discard(cc)
        except Exception as e:
            _sync_error(f"TTL check failed for {cc}: {type(e).__name__}")


def _sync_new_ips(by_country):
    """(b) Add newly seen IPs to each active region's rule (also creates rules for ip_count-0 regions)."""
    for cc, entry in list(_active.items()):
        try:
            if (entry.get("scope") or "observed") == "country":
                continue  # country-wide rules already cover the country's entire IP space
            current = _observed_ips(by_country.get(cc))
            known = set(entry.get("ips") or set())
            if not (set(current) - known):
                continue
            allowed, _ = firewall.filter_ips(known | set(current))
            added = set(allowed) - known
            if not added:
                continue  # only private/never-block/over-cap IPs appeared
            result = firewall.apply_rule(cc, allowed)
            if not result.get("ok"):
                _sync_error(f"Could not add new IPs to geofence {country_name(cc)}.")
                continue
            entry["ips"] = set(allowed)
            _reset_to(by_country.get(cc), added)
            suffix = " (dry-run)" if result.get("dry_run") else ""
            db.append_audit_event("geofence_update", "info",
                                  f"Geofence {country_name(cc)}: blocked {len(added)} new IPs{suffix}", cc)
            _sync_event(cc, "new IPs added", f"Geofence {country_name(cc)}: blocked {len(added)} new IPs{suffix}",
                        {"ip_count": len(entry["ips"])})
        except Exception as e:
            _sync_error(f"New-IP update failed for {cc}: {type(e).__name__}")


def _sync_orphans():
    """(c) Enforced only: remove GeoTrench-* rules in our group that have no active region."""
    if firewall.enforcement_mode()["mode"] != "enforced":
        return
    handled_ccs = set()
    for r in firewall.get_rules():
        cc = r.get("country_code")
        if cc is None or cc in _active or cc in handled_ccs:
            continue  # names we can't map to a code are left for sweep_all()
        handled_ccs.add(cc)
        try:
            if firewall.remove_rule(cc).get("ok"):
                db.append_audit_event("geofence_orphan", "info", f"Removed orphan rule {r['name']}", cc)
                _sync_event(cc, "orphan removed", f"Removed orphan rule {r['name']}", {"rule_name": r["name"]})
            else:
                _sync_error(f"Could not remove orphan rule {r['name']}.")
        except Exception as e:
            _sync_error(f"Orphan cleanup failed for {r.get('name')}: {type(e).__name__}")


def sync_once(now=None):
    """One background sync tick: TTL expiry, new IPs, orphan rules. Never raises.
    `now` (aware UTC datetime) is injectable for tests."""
    now = now or _now()
    started = time.perf_counter()
    try:
        by_country = connections.current_ips_by_country()  # outside the lock: psutil can be slow
    except Exception as e:
        by_country = {}
        _sync_error(f"Could not read current connections: {type(e).__name__}")
    with _lock:
        try:
            _ensure_loaded()
            _sync_ttl(now)
            _sync_new_ips(by_country)
            _sync_orphans()
        except Exception as e:
            _sync_error(f"Sync failed: {type(e).__name__}")
        finally:
            _sync["last_sync_at"] = _iso(now)
            _sync["last_sync_ms"] = round((time.perf_counter() - started) * 1000, 1)


# ---------------------------------------------------------------- startup sweep

def startup_sweep():
    """Before the sync starts: remove leftover GeoTrench-* rules (admin only) and append
    'unblock' (source='startup_sweep') for every region the replayed log still says is blocked,
    so recorded state matches the OS. Never raises. Returns {"rules_removed", "regions_cleared"}."""
    with _lock:
        removed, cleared = [], []
        try:
            if firewall.is_admin():
                removed = firewall.sweep_all()
        except Exception:
            log.exception("Startup firewall sweep failed")
        try:
            for r in db.get_active_geofences():
                cc = r["country_code"]
                db.append_geofence_event(  # bumps geofence_version
                    "unblock", cc, [], r.get("rule_name"), False, None,
                    "Cleared at startup", ip_count=0, mode=r.get("mode"), source="startup_sweep",
                )
                cleared.append(cc)
            if cleared:
                db.append_audit_event("geofence_unblock", "info",
                                      f"Cleared {len(cleared)} geofence(s) left from previous run", None)
        except Exception:
            log.exception("Startup geofence reset failed")
        _active.clear()
        _ttl_failure_logged.clear()
        log.info("Startup sweep: firewall rules removed=%s, geofences cleared=%s", removed, cleared)
        return {"rules_removed": removed, "regions_cleared": cleared}


# ---------------------------------------------------------------- shutdown cleanup

_cleanup_done = False


def atexit_sweep():
    """Last-resort atexit hook: firewall rules only (the DB may already be closed). Never raises."""
    if _cleanup_done:
        return
    try:
        firewall.sweep_all()
    except Exception:
        pass


def shutdown_cleanup():
    """Return the OS to its pre-run state: remove every GeoTrench-* firewall rule (and only those),
    and append 'unblock' events so the replayed state is clean on next start. Runs at most once.
    Never raises. Returns {"rules_removed": [...], "regions_cleared": [...]}."""
    global _cleanup_done
    with _lock:
        if _cleanup_done:
            return {"rules_removed": [], "regions_cleared": []}
        _cleanup_done = True
        removed, cleared = [], []
        try:
            removed = firewall.sweep_all()  # admin only; [] otherwise (dry runs created no rules)
        except Exception:
            log.exception("Shutdown firewall sweep failed")
        try:
            for r in db.get_active_geofences():
                cc = r["country_code"]
                db.append_geofence_event(
                    "unblock", cc, [], r.get("rule_name"), False, None,
                    "Cleared on shutdown", ip_count=0, mode=r.get("mode"), source="shutdown",
                )
                cleared.append(cc)
            if removed or cleared:
                db.append_audit_event(
                    "geofence_unblock", "info",
                    f"Shutdown cleanup: removed {len(removed)} firewall rule(s), cleared {len(cleared)} geofence(s)",
                    None,
                )
        except Exception:
            log.exception("Shutdown geofence reset failed")
        _active.clear()
        log.info("Shutdown cleanup: firewall rules removed=%s, geofences cleared=%s", removed, cleared)
        return {"rules_removed": removed, "regions_cleared": cleared}


# On import: rebuild the in-memory map only (8C adds the startup sweep). The DB may not be
# initialized yet when server.py imports this module; in that case it loads on first use.
try:
    rebuild_state()
except Exception:
    _loaded = False
