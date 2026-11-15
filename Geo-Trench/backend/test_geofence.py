"""Plain-script tests for geofence.py. No PowerShell is executed; uses a temporary database.

Run from backend/:  python test_geofence.py
"""
import json
import os
import shutil
import sys
import tempfile
from unittest import mock

from pydantic import ValidationError

import config
import connections
import db
import firewall
import geofence

results = []


def check(label, actual, expected):
    ok = actual == expected
    results.append(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] {label}" + ("" if ok else f"  (got {actual!r}, expected {expected!r})"))


def _no_powershell(*_a, **_k):
    raise AssertionError("test tried to execute PowerShell")


GATEWAY, DNS = "192.168.1.1", "8.8.4.4"
FAKE_BY_COUNTRY = {
    "DE": {"real_ips": {"1.0.0.5", "1.0.0.6", "10.0.0.9", DNS}, "real_conn_count": 4,
           "simulated_conn_count": 0, "country_name": "Germany"},
    "RO": {"real_ips": set(), "real_conn_count": 0, "simulated_conn_count": 1, "country_name": "Romania"},
    "JP": {"real_ips": {"1.0.0.20"}, "real_conn_count": 1, "simulated_conn_count": 0, "country_name": "Japan"},
}

calls = {"apply": [], "remove": [], "reset": []}
fail = {"apply": False, "remove": False, "remove_ccs": set(), "apply_ccs": set()}


def fake_reset(conns):
    conns = list(conns)
    calls["reset"].append(conns)
    return len(conns)


def fake_apply(cc, ips):
    calls["apply"].append((cc, list(ips)))
    if fail["apply"] or cc in fail["apply_ccs"]:
        return {"ok": False, "message": "Firewall rule could not be created.", "dry_run": False,
                "rule_name": f"GeoTrench-{cc}", "ip_count": 0, "command_display": None}
    return {"ok": True, "message": "Dry run: firewall rule not sent.", "dry_run": True,
            "rule_name": f"GeoTrench-{cc}", "ip_count": len(ips),
            "command_display": firewall.build_display(cc, ips) if ips else None}


def fake_remove(cc):
    calls["remove"].append(cc)
    if fail["remove"] or cc in fail["remove_ccs"]:
        return {"ok": False, "message": "Firewall rule could not be removed.", "dry_run": False,
                "rule_name": f"GeoTrench-{cc}", "ip_count": 0, "command_display": None}
    return {"ok": True, "message": "Dry run: firewall rule not removed.", "dry_run": True,
            "rule_name": f"GeoTrench-{cc}", "ip_count": 0, "command_display": None}


REAL_RESET_TCP = firewall.reset_tcp_connections  # captured before patching; tested with SetTcpEntry mocked
TMP = tempfile.mkdtemp(prefix="geotrench_geofence_")
patches = [
    mock.patch.object(firewall, "_run_ps", _no_powershell),
    mock.patch.object(firewall, "is_admin", lambda: False),
    mock.patch.object(firewall, "get_never_block", lambda: {GATEWAY, DNS}),
    mock.patch.object(firewall, "apply_rule", fake_apply),
    mock.patch.object(firewall, "remove_rule", fake_remove),
    mock.patch.object(firewall, "reset_tcp_connections", fake_reset),
    mock.patch.object(firewall, "get_rules", lambda: []),
    mock.patch.object(connections, "current_ips_by_country", lambda: json.loads(json.dumps(
        {k: {**v, "real_ips": sorted(v["real_ips"]), "recent_ips": sorted(v.get("recent_ips") or ())}
         for k, v in FAKE_BY_COUNTRY.items()}))),
    mock.patch.object(config, "ENFORCE_FIREWALL", False),
    mock.patch.object(config, "KILL_ON_GEOFENCE", False),
    mock.patch.object(config, "RESET_CONNECTIONS_ON_GEOFENCE", False),
    mock.patch.object(config, "RULE_TTL_MINUTES", 30.0),
]
for p in patches:
    p.start()

try:
    db.init_db(os.path.join(TMP, "geofence_test.db"))
    geofence.rebuild_state()

    def blocked_codes():
        return [b["country_code"] for b in geofence.state()[1]["blocked"]]

    # ------------------------------------------------------------ preview
    code, body = geofence.preview("de")
    check("preview: 200 for 'de'", (code, body["country_code"], body["country_name"]), (200, "DE", "Germany"))
    check("preview: only allowed public IPs, sorted", body["ips"], ["1.0.0.5", "1.0.0.6"])
    check("preview: skipped reported as counts only",
          body["skipped_counts"], {"gateway/DNS/never-block host": 1, "private/reserved range": 1})
    text = json.dumps(body)
    check("preview: never contains private, gateway or DNS IPs",
          any(ip in text for ip in ("10.0.0.9", GATEWAY, DNS)), False)
    check("preview: mode dry_run with reason", (body["mode"], body["mode_reason"]),
          ("dry_run", "ENFORCE_FIREWALL is false"))
    check("preview: notes include GeoIP + no-kill",
          [geofence.GEOIP_NOTE, geofence.NO_KILL_NOTE] == body["notes"], True)
    check("preview: command_display uses New-NetFirewallRule",
          (body["command_display"] or "").startswith("New-NetFirewallRule -Name GeoTrench-DE"), True)
    check("preview: real connections affected", body["real_connections_affected"], 4)
    _, ro = geofence.preview("RO")
    check("preview: no real IPs -> ip_count 0, no command, no-IPs note, simulated counted",
          (ro["ip_count"], ro["command_display"], geofence.NO_IPS_NOTE in ro["notes"],
           ro["simulated_connections_affected"]), (0, None, True, 1))
    check("preview: invalid code -> 400", geofence.preview("D'"), (400, {"ok": False, "message": "Invalid country code."}))
    check("preview: empty code -> 400", geofence.preview("")[0], 400)

    # ------------------------------------------------------------ block: confirmation + validation
    code, body = geofence.block("DE", False)
    check("block: confirm=false -> 400 with preview",
          (code, body["message"], body["preview"]["country_code"]), (400, "Confirmation required.", "DE"))
    check("block: confirm='true' (string) is not confirmation", geofence.block("DE", "true")[0], 400)
    check("block: confirm=false did not call the firewall or block", (calls["apply"], blocked_codes()), ([], []))
    check("block: invalid code -> 400", geofence.block("DEU", True)[0], 400)

    # ------------------------------------------------------------ block -> state -> second block -> undo
    code, body = geofence.block("de", True)
    check("block: 200 and message (dry run)",
          (code, body["message"], body["mode"], body["ip_count"], body["rule_name"]),
          (200, "Geofenced Germany. Dry run: no firewall rule sent.", "dry_run", 2, "GeoTrench-DE"))
    check("block: firewall got only allowed IPs", calls["apply"][-1], ("DE", ["1.0.0.5", "1.0.0.6"]))
    check("block: expires_at set", bool(body["expires_at"]), True)
    st = geofence.state()[1]
    check("state: shows DE", blocked_codes(), ["DE"])
    check("state: DE details", (st["blocked"][0]["ip_count"], st["blocked"][0]["mode"], st["blocked"][0]["rule_present"]),
          (2, "dry_run", None))
    check("state: mode fields", (st["mode"], st["enforce_firewall"], st["ttl_minutes"], st["is_admin"]),
          ("dry_run", False, config.RULE_TTL_MINUTES, False))
    check("state: no local/gateway/DNS IPs", any(ip in json.dumps(st) for ip in ("10.0.0.9", GATEWAY, DNS)), False)
    code, body = geofence.block("DE", True)
    check("block: second block -> 409", (code, body["ok"], body["message"], body["op_id"].startswith("geofence-")),
          (409, False, "Region already geofenced.", True))
    check("preview: already_blocked true after block", geofence.preview("DE")[1]["already_blocked"], True)
    check("connections: geofence_version bumped -> blocked regions read DE",
          connections.get_blocked_regions(), ["DE"])

    code, body = geofence.undo("de")
    check("undo: 200", (code, body["message"], body["country_code"]), (200, "Geofence removed for Germany.", "DE"))
    check("state: empty after undo", blocked_codes(), [])
    check("undo: again -> 409 (op_id null: failed before starting)", geofence.undo("DE"),
          (409, {"ok": False, "message": "Region is not geofenced.", "op_id": None}))
    check("undo: no code and nothing active -> 409",
          geofence.undo(), (409, {"ok": False, "message": "No active geofence to undo.", "op_id": None}))
    check("geofence_log rows kept (block + unblock appended, none deleted)", db.row_counts()["geofence_log"], 2)

    # ------------------------------------------------------------ failures
    fail["apply"] = True
    code, body = geofence.block("JP", True)
    fail["apply"] = False
    check("block: failed apply_rule -> 500", (code, body["message"]), (500, "Firewall rule could not be created."))
    check("block: failed apply_rule -> NOT blocked, no geofence_log row",
          (blocked_codes(), db.row_counts()["geofence_log"]), ([], 2))
    check("block: failed apply_rule -> audit event written",
          any(e["type"] == "geofence_failed" for e in db.get_audit_events(50)), True)

    geofence.block("JP", True)
    fail["remove"] = True
    code, body = geofence.undo("JP")
    fail["remove"] = False
    check("undo: failed remove_rule -> 500", (code, body["message"]), (500, "Firewall rule could not be removed."))
    check("undo: failed remove_rule -> still blocked", blocked_codes(), ["JP"])

    # ------------------------------------------------------------ undo with no code picks the most recent
    geofence.block("RO", True)
    check("block: zero-IP region message",
          [e["message"] for e in db.get_audit_events(50) if e["type"] == "geofence_block"][0],
          "Geofenced Romania (0 IPs, dry-run)")
    code, body = geofence.undo()
    check("undo: no code -> most recent (RO)", (code, body["country_code"]), (200, "RO"))
    check("undo: JP still blocked", blocked_codes(), ["JP"])
    geofence.undo()
    check("undo: next no-code undo removes JP", blocked_codes(), [])

    # ------------------------------------------------------------ audit + persistence
    msgs = [e["message"] for e in db.get_audit_events(100)]
    check("audit: 'Geofenced Germany (2 IPs, dry-run)'", "Geofenced Germany (2 IPs, dry-run)" in msgs, True)
    check("audit: 'Removed geofence Germany'", "Removed geofence Germany" in msgs, True)
    check("audit: user geofence rows not double-listed",
          sum(1 for m in msgs if m.startswith("Blocked traffic to") or m.startswith("Unblocked ")), 0)
    geofence.block("DE", True)
    geofence._active.clear()
    geofence.rebuild_state()
    check("rebuild_state: in-memory map restored from the log",
          (sorted(geofence._active), sorted(geofence._active["DE"]["ips"])), (["DE"], ["1.0.0.5", "1.0.0.6"]))

    # ------------------------------------------------------------ request models
    for label, model, payload in [
        ("geofence: extra field", geofence.GeofenceRequest, {"country_code": "DE", "confirm": True, "ips": ["1.1.1.1"]}),
        ("geofence: missing country_code", geofence.GeofenceRequest, {"confirm": True}),
        ("undo: extra field", geofence.UndoRequest, {"country_code": "DE", "force": True}),
    ]:
        try:
            model(**payload)
            check(f"{label} -> 422", "accepted", "rejected")
        except ValidationError:
            check(f"{label} -> 422", "rejected", "rejected")
    check("undo: empty body allowed", geofence.UndoRequest().country_code, None)

    # ------------------------------------------------------------ shutdown cleanup
    geofence.block("JP", True)  # DE is still blocked from the rebuild test above
    rows_before = db.row_counts()["geofence_log"]
    sweeps = []
    with mock.patch.object(firewall, "sweep_all", lambda: sweeps.append(1) or ["GeoTrench-DE", "GeoTrench-JP"]):
        geofence._cleanup_done = False
        out = geofence.shutdown_cleanup()
        again = geofence.shutdown_cleanup()
    check("shutdown: sweeps firewall rules", (out["rules_removed"], len(sweeps)), (["GeoTrench-DE", "GeoTrench-JP"], 1))
    check("shutdown: clears every active geofence", (sorted(out["regions_cleared"]), blocked_codes()), (["DE", "JP"], []))
    check("shutdown: appends unblock rows (none deleted)", db.row_counts()["geofence_log"], rows_before + 2)
    check("shutdown: runs only once", again, {"rules_removed": [], "regions_cleared": []})
    check("shutdown: audit event written",
          any(e["message"].startswith("Shutdown cleanup: removed 2 firewall rule(s), cleared 2")
              for e in db.get_audit_events(50)), True)
    with mock.patch.object(firewall, "sweep_all", lambda: (_ for _ in ()).throw(RuntimeError("boom"))):
        geofence._cleanup_done = False
        check("shutdown: never raises if the sweep fails", isinstance(geofence.shutdown_cleanup(), dict), True)

    # ================================================================ Step 8C
    from datetime import datetime, timedelta, timezone

    def fresh(name):
        db.init_db(os.path.join(TMP, f"{name}.db"))
        geofence.rebuild_state()
        geofence._sync["errors"].clear()
        geofence._ttl_failure_logged.clear()
        for k in ("apply", "remove", "reset"):
            calls[k].clear()
        fail.update({"apply": False, "remove": False, "remove_ccs": set(), "apply_ccs": set()})

    def sources(cc):
        return [r["source"] for r in db._db().execute(
            "SELECT source FROM geofence_log WHERE country_code = ? ORDER BY id", (cc,))]

    def audit_msgs():
        return [e["message"] for e in db.get_audit_events(200)]

    LATER = datetime.now(timezone.utc) + timedelta(minutes=31)

    # ------------------------------------------------------------ preview note follows RESET setting
    with mock.patch.object(config, "RESET_CONNECTIONS_ON_GEOFENCE", True):
        check("8C preview: reset note when reset enabled",
              geofence.RESET_NOTE in geofence.preview("DE")[1]["notes"], True)
    check("8C preview: no-kill note when reset disabled",
          geofence.NO_KILL_NOTE in geofence.preview("DE")[1]["notes"], True)

    # ------------------------------------------------------------ block resets connections to blocked IPs
    fresh("c_block")
    FAKE_BY_COUNTRY["DE"]["conns"] = [
        {"local_ip": "192.168.1.50", "local_port": 50001, "remote_ip": "1.0.0.5", "remote_port": 443, "family": "ipv4"},
        {"local_ip": "192.168.1.50", "local_port": 50002, "remote_ip": "10.0.0.9", "remote_port": 443, "family": "ipv4"},
    ]
    code, body = geofence.block("DE", True)
    check("8C block: response has reset_connections", body.get("reset_connections"), 1)
    check("8C block: reset only for the blocked public IP", [c["remote_ip"] for c in calls["reset"][-1]], ["1.0.0.5"])
    check("8C block: response never includes local IPs", "192.168.1.50" in json.dumps(body), False)

    # ------------------------------------------------------------ TTL expiry
    geofence.sync_once(LATER)
    check("8C TTL: expired region's rule removed", calls["remove"], ["DE"])
    check("8C TTL: unblock row with source 'ttl'", sources("DE"), ["user", "ttl"])
    check("8C TTL: no longer blocked", (db.get_blocked_regions(), "DE" in geofence._active), ([], False))
    check("8C TTL: audit 'Geofence for Germany expired'", "Geofence for Germany expired" in audit_msgs(), True)
    check("8C TTL: not expired yet -> untouched",
          (geofence.block("JP", True)[0], geofence.sync_once(datetime.now(timezone.utc)), calls["remove"]),
          (200, None, ["DE"]))

    # ------------------------------------------------------------ TTL removal failure -> retried, logged once
    fresh("c_ttl_fail")
    geofence.block("JP", True)
    fail["remove_ccs"] = {"JP"}
    geofence.sync_once(LATER)
    geofence.sync_once(LATER)
    check("8C TTL fail: still blocked", db.get_blocked_regions(), ["JP"])
    check("8C TTL fail: retried every tick", calls["remove"], ["JP", "JP"])
    check("8C TTL fail: error recorded once", len(geofence._sync["errors"]), 1)
    fail["remove_ccs"] = set()
    geofence.sync_once(LATER)
    check("8C TTL fail: succeeds on a later tick", (db.get_blocked_regions(), sources("JP")), ([], ["user", "ttl"]))

    # ------------------------------------------------------------ new IP -> union applied, reset only the new IP
    fresh("c_new_ip")
    FAKE_BY_COUNTRY["DE"]["conns"] = []
    geofence.block("DE", True)
    calls["apply"].clear(); calls["reset"].clear()
    FAKE_BY_COUNTRY["DE"]["real_ips"] = {"1.0.0.5", "1.0.0.6", "1.0.0.7", "10.0.0.9", DNS}
    FAKE_BY_COUNTRY["DE"]["conns"] = [
        {"local_ip": "192.168.1.50", "local_port": 50010, "remote_ip": "1.0.0.5", "remote_port": 443, "family": "ipv4"},
        {"local_ip": "192.168.1.50", "local_port": 50011, "remote_ip": "1.0.0.7", "remote_port": 443, "family": "ipv4"},
    ]
    rows_before = db.row_counts()["geofence_log"]
    geofence.sync_once(datetime.now(timezone.utc))
    check("8C new IP: apply_rule called with the union", calls["apply"], [("DE", ["1.0.0.5", "1.0.0.6", "1.0.0.7"])])
    check("8C new IP: reset called for the new IP only", [[c["remote_ip"] for c in r] for r in calls["reset"]], [["1.0.0.7"]])
    check("8C new IP: in-memory ips + state ip_count updated",
          (sorted(geofence._active["DE"]["ips"]), geofence.state()[1]["blocked"][0]["ip_count"]),
          (["1.0.0.5", "1.0.0.6", "1.0.0.7"], 3))
    check("8C new IP: no geofence_log row for IP additions", db.row_counts()["geofence_log"], rows_before)
    check("8C new IP: audit 'blocked 1 new IPs'", any(m.startswith("Geofence Germany: blocked 1 new IPs") for m in audit_msgs()), True)
    calls["apply"].clear()
    geofence.sync_once(datetime.now(timezone.utc))
    check("8C new IP: nothing new -> no apply", calls["apply"], [])
    FAKE_BY_COUNTRY["DE"]["real_ips"] = {"1.0.0.5", "1.0.0.6", "10.0.0.9", DNS}
    FAKE_BY_COUNTRY["DE"]["conns"] = []

    # ------------------------------------------------------------ ip_count-0 region gets its rule once an IP appears
    fresh("c_zero")
    geofence.block("RO", True)
    calls["apply"].clear()
    FAKE_BY_COUNTRY["RO"]["real_ips"] = {"1.0.0.30"}
    geofence.sync_once(datetime.now(timezone.utc))
    check("8C zero-IP region: rule created when an IP appears", calls["apply"], [("RO", ["1.0.0.30"])])
    check("8C zero-IP region: state ip_count 1", geofence.state()[1]["blocked"][0]["ip_count"], 1)
    FAKE_BY_COUNTRY["RO"]["real_ips"] = set()

    # ------------------------------------------------------------ one region failing doesn't stop another
    fresh("c_isolation")
    geofence.block("DE", True)
    geofence.block("JP", True)
    FAKE_BY_COUNTRY["DE"]["real_ips"] = {"1.0.0.5", "1.0.0.6", "1.0.0.8"}
    FAKE_BY_COUNTRY["JP"]["real_ips"] = {"1.0.0.20", "1.0.0.21"}
    fail["apply_ccs"] = {"DE"}
    calls["apply"].clear()
    geofence.sync_once(datetime.now(timezone.utc))
    check("8C isolation: DE failed, JP still updated",
          (sorted(geofence._active["DE"]["ips"]), sorted(geofence._active["JP"]["ips"])),
          (["1.0.0.5", "1.0.0.6"], ["1.0.0.20", "1.0.0.21"]))
    fail["apply_ccs"] = set()
    fail["remove_ccs"] = {"DE"}
    geofence.sync_once(LATER)
    check("8C isolation: DE TTL removal failed, JP still expired", db.get_blocked_regions(), ["DE"])
    check("8C isolation: sync_errors bounded to 5 and message-only",
          all(isinstance(e, str) for e in geofence._sync["errors"]) and len(geofence._sync["errors"]) <= 5, True)
    FAKE_BY_COUNTRY["DE"]["real_ips"] = {"1.0.0.5", "1.0.0.6", "10.0.0.9", DNS}
    FAKE_BY_COUNTRY["JP"]["real_ips"] = {"1.0.0.20"}

    # ------------------------------------------------------------ orphan rules (enforced only)
    fresh("c_orphan")
    geofence.block("DE", True)
    calls["remove"].clear()
    rules = [{"name": "GeoTrench-KP", "country_code": "KP"}, {"name": "GeoTrench-DE", "country_code": "DE"}]
    with mock.patch.object(firewall, "get_rules", lambda: rules):
        geofence.sync_once(datetime.now(timezone.utc))
        check("8C orphan: dry run leaves rules alone", calls["remove"], [])
        with mock.patch.object(firewall, "enforcement_mode", lambda: {"mode": "enforced", "reason": "test"}):
            geofence.sync_once(datetime.now(timezone.utc))
    check("8C orphan: only the rule without an active region removed", calls["remove"], ["KP"])
    check("8C orphan: audit 'Removed orphan rule GeoTrench-KP'", "Removed orphan rule GeoTrench-KP" in audit_msgs(), True)

    # ------------------------------------------------------------ state sync fields
    st = geofence.state()[1]
    check("8C state: sync fields present",
          all(k in st for k in ("last_sync_at", "last_sync_ms", "sync_errors", "sync_seconds", "reset_connections_enabled")),
          True)
    check("8C state: seconds_remaining for an active region", 0 < st["blocked"][0]["seconds_remaining"] <= 30 * 60, True)

    # ------------------------------------------------------------ startup sweep
    fresh("c_startup")
    geofence.block("DE", True)
    geofence.block("JP", True)
    swept = []
    with mock.patch.object(firewall, "is_admin", lambda: True), \
            mock.patch.object(firewall, "sweep_all", lambda: swept.append(1) or ["GeoTrench-DE"]):
        out = geofence.startup_sweep()
    check("8C startup: sweeps OS rules when admin", (len(swept), out["rules_removed"]), (1, ["GeoTrench-DE"]))
    check("8C startup: appends startup_sweep rows for leftovers",
          (sources("DE"), sources("JP"), db.get_blocked_regions()),
          (["user", "startup_sweep"], ["user", "startup_sweep"], []))
    check("8C startup: in-memory map cleared", geofence._active, {})
    check("8C startup: audit 'Cleared 2 geofence(s) left from previous run'",
          "Cleared 2 geofence(s) left from previous run" in audit_msgs(), True)
    swept.clear()
    with mock.patch.object(firewall, "sweep_all", lambda: swept.append(1) or []):
        geofence.startup_sweep()
    check("8C startup: not admin -> no OS sweep", swept, [])

    # ------------------------------------------------------------ shutdown idempotent + atexit
    fresh("c_shutdown")
    geofence.block("DE", True)
    geofence._cleanup_done = False
    with mock.patch.object(firewall, "sweep_all", lambda: []):
        first = geofence.shutdown_cleanup()
        second = geofence.shutdown_cleanup()
    check("8C shutdown: first call clears, second is a no-op",
          (first["regions_cleared"], second), (["DE"], {"rules_removed": [], "regions_cleared": []}))
    atexit_calls = []
    with mock.patch.object(firewall, "sweep_all", lambda: atexit_calls.append(1)):
        geofence.atexit_sweep()
    check("8C atexit: skipped after shutdown cleanup already ran", atexit_calls, [])

    # ------------------------------------------------------------ recently seen IPs are blocked too
    fresh("c_recent")
    FAKE_BY_COUNTRY["IN"] = {"real_ips": {"1.0.0.40"}, "recent_ips": {"1.0.0.40", "1.0.0.41", "1.0.0.42", "10.0.0.7"},
                             "real_conn_count": 1, "simulated_conn_count": 0, "country_name": "India", "conns": []}
    _, pv = geofence.preview("IN")
    check("recent: preview counts live + recent public IPs", (pv["ip_count"], pv["recent_ip_count"]), (3, 2))
    check("recent: private recent IP never included", "10.0.0.7" in pv["ips"], False)
    geofence.block("IN", True)
    check("recent: block applies live + recent IPs", calls["apply"][-1], ("IN", ["1.0.0.40", "1.0.0.41", "1.0.0.42"]))
    with mock.patch.object(connections, "recent_process_for", lambda ip: "chrome.exe"), \
            mock.patch.object(geofence.geo, "geolocate",
                              lambda ip: {"city": "Mumbai", "country_code": "IN", "asn_org": "Test ISP"}):
        st = geofence.state()[1]
    bl = st["blocked"][0]["blocked_ips"]
    check("state: blocked_ips lists each server with location + process",
          bl[0], {"ip": "1.0.0.40", "city": "Mumbai", "country_code": "IN", "asn_org": "Test ISP", "process": "chrome.exe"})
    check("state: blocked_ips has no private/local IPs", any(x["ip"].startswith(("10.", "192.168.")) for x in bl), False)
    calls["apply"].clear()
    geofence.sync_once(datetime.now(timezone.utc))
    check("recent: sync doesn't re-apply when nothing new", calls["apply"], [])
    del FAKE_BY_COUNTRY["IN"]

    # ------------------------------------------------------------ reset_tcp_connections (SetTcpEntry mocked)
    import socket
    import struct
    rows = []

    def fake_set(row):
        rows.append(row)
        return 5 if row.dwLocalPort == socket.htons(50099) else 0  # simulate one failure

    conns = [
        {"local_ip": "192.168.1.50", "local_port": 50001, "remote_ip": "1.0.0.5", "remote_port": 443, "family": "ipv4"},
        {"local_ip": "fe80::1", "local_port": 50002, "remote_ip": "2606:4700::1", "remote_port": 443, "family": "ipv6"},
        {"local_ip": "192.168.1.50", "local_port": 50003, "remote_ip": "10.0.0.9", "remote_port": 443, "family": "ipv4"},
        {"local_ip": "192.168.1.50", "local_port": 50004, "remote_ip": DNS, "remote_port": 53, "family": "ipv4"},
        {"local_ip": "192.168.1.50", "local_port": 50099, "remote_ip": "1.0.0.6", "remote_port": 443, "family": "ipv4"},
    ]
    real_reset = REAL_RESET_TCP
    with mock.patch.object(firewall, "_set_tcp_entry", fake_set), \
            mock.patch.object(firewall, "_enforced", lambda: True), \
            mock.patch.object(config, "RESET_CONNECTIONS_ON_GEOFENCE", True):
        n = real_reset(conns)
    check("8C reset: counts only successful public IPv4 resets", n, 1)
    check("8C reset: SetTcpEntry called for public IPv4 only (skips IPv6, private, DNS)",
          sorted(socket.ntohs(r.dwRemotePort) for r in rows), [443, 443])
    first_row = rows[0]
    check("8C reset: MIB_TCPROW packing",
          (first_row.dwState, first_row.dwRemoteAddr, first_row.dwRemotePort, first_row.dwLocalAddr, first_row.dwLocalPort),
          (12, struct.unpack("<I", socket.inet_aton("1.0.0.5"))[0], socket.htons(443),
           struct.unpack("<I", socket.inet_aton("192.168.1.50"))[0], socket.htons(50001)))
    rows.clear()
    with mock.patch.object(firewall, "_set_tcp_entry", fake_set), \
            mock.patch.object(config, "RESET_CONNECTIONS_ON_GEOFENCE", True):
        check("8C reset: dry run -> 0 and no SetTcpEntry calls", (real_reset(conns), rows), (0, []))
    with mock.patch.object(firewall, "_set_tcp_entry", fake_set), \
            mock.patch.object(firewall, "_enforced", lambda: True), \
            mock.patch.object(config, "RESET_CONNECTIONS_ON_GEOFENCE", False):
        check("8C reset: disabled by config -> 0 and no calls", (real_reset(conns), rows), (0, []))
    with mock.patch.object(firewall, "_set_tcp_entry", lambda row: (_ for _ in ()).throw(OSError("x"))), \
            mock.patch.object(firewall, "_enforced", lambda: True), \
            mock.patch.object(config, "RESET_CONNECTIONS_ON_GEOFENCE", True):
        check("8C reset: never raises", real_reset(conns), 0)
finally:
    for p in reversed(patches):
        p.stop()
    db.close()
    shutil.rmtree(TMP, ignore_errors=True)

passed = sum(results)
print(f"\n{passed}/{len(results)} passed" + ("" if passed == len(results) else "  <-- FAILURES"))
sys.exit(0 if passed == len(results) else 1)
