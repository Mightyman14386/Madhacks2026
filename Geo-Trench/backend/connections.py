"""Builds the /api/connections snapshot: live outbound traffic, classified and geolocated.

Never raises: failures degrade to empty lists plus a warning string.
raw_exe and cmdline are used server-side only and are never put in the response.
"""
import hashlib
import logging
import ntpath
import os
import socket
import threading
import time
from datetime import datetime, timezone

import psutil

import ancestry
import config
import databricks_export
import db
import geo
import quarantine_guards
import scenarios
from threats import classify

log = logging.getLogger("geotrench.connections")

MAX_CONNECTIONS = 150
FIRST_SEEN_TTL_SECONDS = 60.0
BLOCKED_CACHE_SECONDS = 1.0

_first_seen = {}  # id -> (first_seen_iso, last_seen_monotonic)
_first_seen_lock = threading.Lock()

# Cache of db.get_blocked_regions(): (fetched_monotonic, geofence_version, regions)
_blocked_cache = None
_blocked_lock = threading.Lock()

# Cache of the last per-country IP summary: (built_monotonic, {cc: {...}})
IPS_BY_COUNTRY_TTL_SECONDS = 3.0
_ips_by_country_cache = None
_ips_by_country_lock = threading.Lock()


# ---------------------------------------------------------------- blocked regions

def get_blocked_regions():
    """Current blocked regions from the geofence log. Cached 1s; any geofence append invalidates.

    Raises if the database is unavailable; get_snapshot() turns that into a warning.
    """
    global _blocked_cache
    with _blocked_lock:
        now = time.monotonic()
        version = db.geofence_version()
        if (_blocked_cache is not None and _blocked_cache[1] == version
                and now - _blocked_cache[0] < BLOCKED_CACHE_SECONDS):
            return list(_blocked_cache[2])
        regions = db.get_blocked_regions()
        _blocked_cache = (now, version, regions)
        return list(regions)


# ---------------------------------------------------------------- protection

def is_protected_process(raw_exe, pid, name):
    """True if this process must never be quarantined or killed. Fails closed.

    Delegates to quarantine_guards so there is one source of truth.
    """
    return quarantine_guards.is_protected_target(raw_exe, pid, name)


# ---------------------------------------------------------------- helpers

def _conn_id(local_ip, local_port, remote_ip, remote_port, pid):
    key = f"{local_ip}:{local_port}|{remote_ip}:{remote_port}|{pid}"
    return hashlib.sha1(key.encode("utf-8")).hexdigest()[:12]


def _touch_first_seen(ids):
    now_mono = time.monotonic()
    now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")
    out = {}
    with _first_seen_lock:
        for cid in ids:
            first = _first_seen.get(cid, (now_iso, now_mono))[0]
            _first_seen[cid] = (first, now_mono)
            out[cid] = first
        for cid in [c for c, (_, seen) in _first_seen.items() if now_mono - seen > FIRST_SEEN_TTL_SECONDS]:
            del _first_seen[cid]
    return out


def _live_sockets(warnings):
    """Return [(pid, local_ip, local_port, remote_ip, remote_port)] for public ESTABLISHED sockets."""
    try:
        raw = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        warnings.append("Access denied listing network connections; run as Administrator.")
        return []
    except Exception as e:
        warnings.append(f"Could not list network connections: {type(e).__name__}")
        return []

    out = []
    for c in raw:
        try:
            if c.status != psutil.CONN_ESTABLISHED or not c.raddr or not c.pid:
                continue
            if geo.classify_ip(c.raddr.ip) != "public":
                continue
            out.append((c.pid, c.laddr.ip, c.laddr.port, c.raddr.ip, c.raddr.port))
        except Exception:
            continue
    return out


# ---------------------------------------------------------------- snapshot

def _collect(warnings):
    """Gather live + planted connections as internal records. Records INCLUDE raw_exe:
    server-side only, never return them to a client as-is."""
    candidates = {}  # id -> record (dedupes identical tuples)

    proc_cache = {}  # pid -> (info, is_protected), once per request
    geo_cache = {}   # ip -> geolocate result, once per request

    def proc(pid):
        if pid not in proc_cache:
            info = ancestry.get_process_info(pid)
            try:
                create_time = psutil.Process(pid).create_time()
            except Exception:
                create_time = None
            proc_cache[pid] = (info, is_protected_process(info.get("raw_exe"), pid, info.get("name")), create_time)
        return proc_cache[pid]

    def locate(ip):
        if ip not in geo_cache:
            geo_cache[ip] = geo.geolocate(ip)
        return geo_cache[ip]

    # Live traffic.
    for pid, lip, lport, rip, rport in _live_sockets(warnings):
        cid = _conn_id(lip, lport, rip, rport, pid)
        if cid in candidates:
            continue
        info, protected, create_time = proc(pid)
        candidates[cid] = {
            "id": cid, "pid": pid,
            "create_time": create_time,  # server-side only; used to detect PID reuse
            "process_name": info.get("name") or "unknown",
            "exe": info.get("exe"),
            "raw_exe": info.get("raw_exe"),  # server-side only; stripped below
            "ancestry": info.get("ancestry") or ["unknown"],
            "ancestry_detail": info.get("ancestry_detail") or [],
            "local_ip": lip, "local_port": lport, "remote_ip": rip, "remote_port": rport,
            "geo": locate(rip),
            "is_protected": protected,
            "is_simulated": False,
        }

    # Planted demo threats: same classify/is_protected path, geo from the override table.
    try:
        for p in scenarios.get_planted_connections():
            cid = _conn_id(p["local_ip"], p["local_port"], p["remote_ip"], p["remote_port"], p["pid"])
            candidates[cid] = {
                "id": cid, "pid": p["pid"],
                "create_time": None,
                "process_name": p["process_name"],
                "exe": p["exe"],
                "raw_exe": p["raw_exe"],
                "ancestry": p["ancestry"],
                "ancestry_detail": p["ancestry_detail"],
                "local_ip": p["local_ip"], "local_port": p["local_port"],
                "remote_ip": p["remote_ip"], "remote_port": p["remote_port"],
                "geo": p["geo"],
                "is_protected": is_protected_process(p["raw_exe"], p["pid"], p["process_name"]),
                "is_simulated": True,
            }
    except Exception as e:
        warnings.append(f"Could not load demo scenarios: {type(e).__name__}")
    return candidates


def _new_country_entry():
    return {"real_ips": set(), "real_conn_count": 0, "simulated_conn_count": 0,
            "country_name": None, "conns": []}


def _summarize_by_country():
    """UNFILTERED per-country view for the geofence sync (blocked countries are included).

    {cc: {"real_ips": set, "real_conn_count": int, "simulated_conn_count": int, "country_name": str|None,
          "conns": [{local_ip, local_port, remote_ip, remote_port, family}]}}

    - Every socket state with a public remote address counts (SYN_SENT, ESTABLISHED, ...), so blocked
      connection attempts are noticed.
    - real_ips excludes simulated connections, anycast/CDN IPs and entries with no country.
    - "conns" lists real TCP connections only. It holds local addresses, so it is SERVER-SIDE ONLY:
      used by firewall.reset_tcp_connections and never returned by any API.
    """
    out = {}
    try:
        raw = psutil.net_connections(kind="inet")
    except Exception as e:
        log.warning("Could not list connections for geofence sync: %s", type(e).__name__)
        raw = []
    for c in raw:
        try:
            if not c.raddr or geo.classify_ip(c.raddr.ip) != "public":
                continue
            g = geo.geolocate(c.raddr.ip) or {}
            cc = (g.get("country_code") or "").upper()
            if not cc or g.get("anycast") or g.get("lat") is None or g.get("lng") is None:
                continue
            entry = out.setdefault(cc, _new_country_entry())
            entry["country_name"] = entry["country_name"] or g.get("country_name")
            entry["real_ips"].add(c.raddr.ip)
            entry["real_conn_count"] += 1
            if c.type == socket.SOCK_STREAM:
                entry["conns"].append({
                    "local_ip": c.laddr.ip, "local_port": c.laddr.port,
                    "remote_ip": c.raddr.ip, "remote_port": c.raddr.port,
                    "family": "ipv6" if c.family == socket.AF_INET6 else "ipv4",
                })
        except Exception:
            continue

    try:
        for p in scenarios.get_planted_connections():
            cc = ((p.get("geo") or {}).get("country_code") or "").upper()
            if cc:
                entry = out.setdefault(cc, _new_country_entry())
                entry["country_name"] = entry["country_name"] or p["geo"].get("country_name")
                entry["simulated_conn_count"] += 1
    except Exception:
        pass
    return out


def current_ips_by_country():
    """Per-country remote IPs, unfiltered by geofence. Cached for 3 s. Server-side use only."""
    global _ips_by_country_cache
    with _ips_by_country_lock:
        cached = _ips_by_country_cache
        if cached is None or time.monotonic() - cached[0] >= IPS_BY_COUNTRY_TTL_SECONDS:
            cached = (time.monotonic(), _summarize_by_country())
            _ips_by_country_cache = cached
        summary = cached[1]
    return {cc: {**v, "real_ips": set(v["real_ips"]), "conns": [dict(x) for x in v["conns"]]}
            for cc, v in summary.items()}


def get_internal_connection(conn_id):
    """Fresh server-side lookup of one current connection by id, including raw_exe.

    Returns None if the connection is not currently open. For server-side decisions only.
    """
    return _collect([]).get(conn_id)


def get_snapshot():
    started = time.perf_counter()
    warnings = []
    candidates = _collect(warnings)

    first_seen = _touch_first_seen(candidates.keys())
    try:
        blocked = set(get_blocked_regions())
    except Exception as e:
        log.warning("Could not read blocked regions: %s", e)
        warnings.append("Could not read blocked regions from the database; geofence not applied.")
        blocked = set()

    connections, anycast, hidden = [], [], 0
    findings = []  # unsafe connections to record (redacted fields only)
    for cid, rec in candidates.items():
        verdict = classify(rec)
        g = rec["geo"]
        if verdict["status"] == "unsafe":
            findings.append({
                "id": cid, "pid": rec["pid"], "process_name": rec["process_name"],
                "remote_ip": rec["remote_ip"], "remote_port": rec["remote_port"],
                "country_code": (g or {}).get("country_code"), "city": (g or {}).get("city"),
                "lat": (g or {}).get("lat"), "lng": (g or {}).get("lng"),  # used by databricks_export only
                "asn_org": (g or {}).get("asn_org"),
                "ancestry": rec["ancestry"],
                "rules_fired": verdict["rules_fired"], "reasons": verdict["reasons"],
                "severity": verdict["severity"],
                "first_seen": first_seen.get(cid),
                "is_simulated": rec["is_simulated"],
            })
        if g is None:
            continue  # no location at all: cannot place it
        if g.get("lat") is None or g.get("lng") is None:
            anycast.append({
                "id": cid, "pid": rec["pid"], "process_name": rec["process_name"],
                "remote_ip": rec["remote_ip"], "remote_port": rec["remote_port"],
                "provider": g.get("anycast_provider"), "asn_org": g.get("asn_org"),
                "status": verdict["status"], "severity": verdict["severity"],
                "rules_fired": verdict["rules_fired"], "reasons": verdict["reasons"],
            })
            continue
        if g.get("country_code") and g["country_code"].upper() in blocked:
            hidden += 1
            continue
        connections.append({
            "id": cid, "pid": rec["pid"], "process_name": rec["process_name"],
            "exe": rec["exe"],
            "ancestry": rec["ancestry"], "ancestry_detail": rec["ancestry_detail"],
            "local_port": rec["local_port"],  # local_ip is never returned (privacy)
            "remote_ip": rec["remote_ip"], "remote_port": rec["remote_port"],
            "country_code": g.get("country_code"), "country_name": g.get("country_name"),
            "city": g.get("city"), "asn_org": g.get("asn_org"),
            "lat": g["lat"], "lng": g["lng"],
            "status": verdict["status"], "severity": verdict["severity"],
            "rules_fired": verdict["rules_fired"], "reasons": verdict["reasons"],
            "is_protected": rec["is_protected"], "is_simulated": rec["is_simulated"],
            "first_seen": first_seen.get(cid),
        })

    try:
        for f in findings:
            if db.upsert_finding(f):  # True only on first sight -> export once
                databricks_export.enqueue(f)
    except Exception as e:
        log.warning("Could not record findings: %s", e)
        warnings.append("Could not record threat findings to the database.")

    connections.sort(key=lambda c: (c["status"] != "unsafe", c["id"]))
    try:
        # Mirror every route the device globe draws into Databricks (same origin + GeoIP point).
        databricks_export.observe_connections(connections, geo.get_origin())
    except Exception as e:
        log.warning("Could not queue connections for Databricks export: %s", type(e).__name__)
    anycast.sort(key=lambda c: (c["status"] != "unsafe", c["id"]))

    unsafe_count = sum(1 for c in connections if c["status"] == "unsafe")
    stats = {
        "total": len(connections),
        "safe": len(connections) - unsafe_count,
        "unsafe": unsafe_count,
        "anycast": len(anycast),
        "hidden_by_geofence": hidden,
        "blocked_regions": sorted(blocked),
    }

    truncated = False
    if len(connections) > MAX_CONNECTIONS:
        unsafe = [c for c in connections if c["status"] == "unsafe"]
        safe = [c for c in connections if c["status"] != "unsafe"]
        connections = unsafe + safe[: max(0, MAX_CONNECTIONS - len(unsafe))]
        truncated = True

    return {
        "origin": geo.get_origin(),
        "connections": connections,
        "anycast": anycast,
        "stats": stats,
        "geoip_fallback": geo.geoip_is_fallback,
        "truncated": truncated,
        "warnings": warnings,
        "generated_ms": round((time.perf_counter() - started) * 1000, 1),
    }
