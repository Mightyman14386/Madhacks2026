"""Plain-script tests for events.py and the live-op instrumentation. No PowerShell, no real processes.

Run from backend/:  python test_events.py
"""
import asyncio
import getpass
import os
import shutil
import sys
import tempfile
from unittest import mock

import config
import connections
import db
import events
import firewall
import geofence
import quarantine
import server

results = []


def check(label, actual, expected):
    ok = actual == expected
    results.append(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] {label}" + ("" if ok else f"  (got {actual!r}, expected {expected!r})"))


events._reset_for_tests()

# ------------------------------------------------------------ deterministic op ids
check("op ids: deterministic per kind",
      [events.start_op("quarantine"), events.start_op("quarantine"), events.start_op("geofence"),
       events.start_op("quarantine")],
      ["quarantine-1", "quarantine-2", "geofence-1", "quarantine-3"])
check("op ids: unknown kind maps to sync", events.start_op("bogus").startswith("sync-"), True)

# ------------------------------------------------------------ sanitize
user = getpass.getuser()
clean = events.sanitize({
    "path": r"C:\Users\someone\AppData\Local\Temp\x.exe",
    "unc": r"\\server\share\x.exe",
    "fwd": "c:/windows/system32/cmd.exe",
    "user": f"owned by {user}",
    "lan": "talking to 192.168.1.50",
    "loop": "127.0.0.1",
    "v6": "fe80::1",
    "public": "203.0.113.66 is fine? no: TEST-NET is private",
    "real_public": "1.0.0.5",
    "plain": "Quarantined payload.exe",
    "num": 42, "nested": {"list": ["ok", r"D:\secret\a.txt"]},
}, _never_block={"8.8.4.4"})
check("sanitize: Windows paths dropped", (clean["path"], clean["unc"], clean["fwd"]), (None, None, None))
check("sanitize: username dropped", clean["user"] if len(user) >= 3 else None, None)
check("sanitize: private/loopback/link-local IPs dropped", (clean["lan"], clean["loop"], clean["v6"]), (None, None, None))
check("sanitize: TEST-NET (documentation) counts as private", clean["public"], None)
check("sanitize: public IP and plain text kept", (clean["real_public"], clean["plain"], clean["num"]),
      ("1.0.0.5", "Quarantined payload.exe", 42))
check("sanitize: nested values", clean["nested"]["list"], ["ok", None])
check("sanitize: gateway/DNS (never-block) IP dropped",
      events.sanitize("dns 8.8.4.4", _never_block={"8.8.4.4"}), None)
check("sanitize: timestamps are not mistaken for IPv6",
      events.sanitize("2026-11-15T11:14:50.123+00:00", _never_block=set()), "2026-11-15T11:14:50.123+00:00")

# ------------------------------------------------------------ bounded buffer + resume
events._reset_for_tests()
op = events.start_op("sync")
for i in range(700):
    events.step(op, "tick", f"step {i}")
buf = events.recent(500)
check("buffer: bounded to 500", (len(events.recent(1000)), len(buf)), (500, 500))
check("buffer: ids keep increasing", (buf[0]["id"], buf[-1]["id"]), (202, 701))
check("recent: newest-last, limit honored", [e["id"] for e in events.recent(3)], [699, 700, 701])
check("since: only newer events", [e["id"] for e in events.since(698)], [699, 700, 701])
check("since: last_id older than buffer -> everything buffered", len(events.since(5)), 500)
check("parse_last_id: header wins over query", events.parse_last_id("12", "99"), 12)
check("parse_last_id: query used when no header", events.parse_last_id(None, "99"), 99)
check("parse_last_id: junk -> None", events.parse_last_id("abc", ""), None)
check("op_events: unknown op -> []", events.op_events("quarantine-999"), [])

e = events.recent(1)[0]
check("event shape", sorted(e), sorted(["id", "ts", "type", "op_id", "kind", "target", "is_simulated", "step",
                                        "message", "status", "elapsed_ms", "data"]))
check("event ts: UTC ISO with ms", (e["ts"].endswith("+00:00"), len(e["ts"].split(".")[1]) >= 3), (True, True))


# ------------------------------------------------------------ SSE generator
async def collect_stream(last_id, actions, disconnect_after=None):
    calls = {"n": 0}

    async def is_disconnected():
        calls["n"] += 1
        return disconnect_after is not None and calls["n"] > disconnect_after

    out = []
    gen = events.sse_stream(is_disconnected, last_id, poll_seconds=0.01, ping_seconds=0.03)

    async def consume():
        async for chunk in gen:
            out.append(chunk)

    task = asyncio.create_task(consume())
    for action in actions:
        await asyncio.sleep(0.05)
        action()
    await asyncio.wait_for(task, timeout=2.0)
    return out


events._reset_for_tests()
op = events.start_op("restore", {"manifest_id": 3})
events.step(op, "verifying record", "Checking the quarantine record.")
events.end_op(op, True, "Restored to original location. Not relaunched.")
out = asyncio.run(collect_stream(1, [events.shutdown]))
frames = [c for c in out if c.startswith("id: ")]
check("stream: starts with retry hint", out[0], "retry: 2000\n\n")
check("stream: resume after last_id=1 sends ids 2,3", [f.split("\n")[0] for f in frames], ["id: 2", "id: 3"])
check("stream: frame format id/event/data", frames[1].split("\n")[1], "event: op_end")
check("stream: exits on shutdown flag (no hang)", True, True)
check("stream: ': ping' comments sent", any(c == ": ping\n\n" for c in out), True)

events._reset_for_tests()
events.start_op("sync")
out = asyncio.run(collect_stream(None, [lambda: events.emit_connections_changed("test")], disconnect_after=8))
frames = [c for c in out if c.startswith("id: ")]
check("stream: no last_id -> starts after newest, sees only new events",
      [f.split("\n")[1] for f in frames], ["event: connections_changed"])
check("stream: exits on client disconnect", True, True)

# ------------------------------------------------------------ live ops from quarantine (mocked lookups)
events._reset_for_tests()
TMP = tempfile.mkdtemp(prefix="geotracker_events_")
try:
    db.init_db(os.path.join(TMP, "events.db"))
    protected_rec = {"id": "aaaaaaaaaaaa", "pid": -1004, "process_name": "rundll32.exe",
                     "raw_exe": r"C:\Windows\System32\rundll32.exe", "is_simulated": True}
    with mock.patch.object(connections, "get_internal_connection", lambda cid: dict(protected_rec)):
        code, body = quarantine.quarantine_connection("aaaaaaaaaaaa")
    seq = events.op_events(body["op_id"])
    check("quarantine protected: response unchanged + op_id",
          (code, body["message"], body["op_id"]), (403, quarantine.PROTECTED_MESSAGE, "quarantine-1"))
    check("quarantine protected: op_start, one failed step (exact message), op_end failed",
          [(e["type"], e["status"], e["message"]) for e in seq],
          [("op_start", "running", "quarantine started"),
           ("op_step", "running", "Checking the connection and its process."),
           ("op_step", "failed", quarantine.PROTECTED_MESSAGE),
           ("op_end", "failed", quarantine.PROTECTED_MESSAGE)])
    check("quarantine protected: target + is_simulated on events",
          (seq[-1]["target"], seq[-1]["is_simulated"]), ({"conn_id": "aaaaaaaaaaaa"}, True))
    check("quarantine protected: no path anywhere in events", any("rundll32.exe" in str(e["data"] or "") or
          "System32" in str(e) for e in seq), False)

    sim_rec = {"id": "bbbbbbbbbbbb", "pid": -1002, "process_name": "payload.exe",
               "raw_exe": r"C:\ProgramData\payload.exe", "is_simulated": True}
    with mock.patch.object(connections, "get_internal_connection", lambda cid: dict(sim_rec)):
        code, body = quarantine.quarantine_connection("bbbbbbbbbbbb")
    seq = events.op_events(body["op_id"])
    check("quarantine simulated: 200 dry run, op ends ok + SIMULATED",
          (code, body["simulated"], seq[-1]["type"], seq[-1]["status"], seq[-1]["is_simulated"]),
          (200, True, "op_end", "ok", True))
    check("quarantine simulated: connections_changed emitted",
          events.recent(1)[0]["type"], "connections_changed")

    with mock.patch.object(connections, "get_internal_connection", lambda cid: None):
        code, body = quarantine.quarantine_connection("cccccccccccc")
    check("quarantine not found: exact message, op ends failed",
          (code, body["message"], events.op_events(body["op_id"])[-1]["status"]),
          (404, "Connection not found or already closed.", "failed"))

    code, body = quarantine.restore_quarantined(999)
    check("restore missing: exact message + op_id",
          (code, body["message"], body["op_id"]), (404, "Quarantine record not found.", "restore-1"))

    # ------------------------------------------------------------ geofence op steps (dry run, mocked firewall)
    fake_by_country = {"DE": {"real_ips": {"1.0.0.5"}, "real_conn_count": 1, "simulated_conn_count": 0,
                              "country_name": "Germany", "conns": []}}
    with mock.patch.object(firewall, "_run_ps", lambda *a, **k: (_ for _ in ()).throw(AssertionError("PS"))), \
            mock.patch.object(firewall, "is_admin", lambda: False), \
            mock.patch.object(firewall, "get_never_block", lambda: set()), \
            mock.patch.object(connections, "current_ips_by_country", lambda: fake_by_country), \
            mock.patch.object(config, "ENFORCE_FIREWALL", False):
        geofence.rebuild_state()
        code, body = geofence.block("DE", True)
        steps = [(e["step"], e["status"]) for e in events.op_events(body["op_id"]) if e["type"] == "op_step"]
        check("geofence: op_id + real step order",
              (code, body["op_id"], steps),
              (200, "geofence-1", [("collecting IPs", "ok"), ("applying rule", "running"), ("rule applied", "ok"),
                                   ("resetting connections", "running"), ("resetting connections", "ok"),
                                   ("verified", "ok")]))
        check("geofence: confirm missing -> op_id null", geofence.block("DE", False)[1]["op_id"], None)
        code, body = geofence.undo("DE")
        check("undo_geofence: steps",
              [e["step"] for e in events.op_events(body["op_id"]) if e["type"] == "op_step"],
              ["removing rule", "removing rule", "verified gone"])
        check("undo_geofence: not geofenced -> op_id null", geofence.undo("DE")[1]["op_id"], None)
finally:
    db.close()
    shutil.rmtree(TMP, ignore_errors=True)

# ------------------------------------------------------------ capabilities + endpoints
caps = server.capabilities()
check("capabilities: stop_process not implemented", caps["features"]["stop_process"], False)
check("capabilities: fields", sorted(caps), sorted(["is_admin", "firewall_mode", "firewall_mode_reason", "demo_mode",
                                                   "geoip_fallback", "reset_connections_enabled", "ttl_minutes",
                                                   "features"]))
check("ops/{op_id}: unknown -> 404", server.op_detail("nope-1").status_code, 404)
check("events/recent: capped at 500", len(server.events_recent(10_000)) <= 500, True)
check("CORS: origins from config", config.CORS_ORIGINS[:2], ("http://localhost:5173", "http://127.0.0.1:5173"))

passed = sum(results)
print(f"\n{passed}/{len(results)} passed" + ("" if passed == len(results) else "  <-- FAILURES"))
sys.exit(0 if passed == len(results) else 1)
