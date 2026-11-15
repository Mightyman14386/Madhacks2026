"""Plain-script tests for db.py. Uses a temporary database, never backend/geotrench.db.

Run from backend/:  python test_db.py
"""
import json
import shutil
import sys
import tempfile
from pathlib import Path

import db

TMP_DIR = Path(tempfile.mkdtemp(prefix="geotrench_test_"))
results = []


def fresh_db(name):
    db.init_db(TMP_DIR / f"{name}.db")


def check(label, ok, detail=""):
    results.append(bool(ok))
    print(f"[{'PASS' if ok else 'FAIL'}] {label}" + (f"  ({detail})" if detail else ""))


def finding(conn_id, **extra):
    base = {
        "id": conn_id, "pid": -1, "process_name": "evil.exe", "remote_ip": "203.0.113.5",
        "remote_port": 4444, "country_code": "RU", "city": "Moscow", "asn_org": "Test Org",
        "ancestry": ["explorer.exe", "evil.exe"], "rules_fired": ["suspicious_port"],
        "reasons": ["Connected over port 4444."], "severity": "medium",
        "first_seen": None, "is_simulated": True,
    }
    base.update(extra)
    return base


def all_rows_text():
    c = db._db()
    dump = []
    for t in ("threat_findings", "geofence_log", "quarantine_manifest", "agent_actions"):
        dump += [dict(r) for r in c.execute("SELECT * FROM " + t)]  # test-only, fixed names
    return json.dumps(dump)


def set_ts(table_sql, row_id, ts):
    # test-only: backdate a row so purge sees it as old
    db._db().execute(table_sql, (ts, row_id))
    db._db().commit()


try:
    # 1. upsert returns True first, False after
    fresh_db("upsert")
    first = db.upsert_finding(finding("aaaaaaaaaaaa"))
    second = db.upsert_finding(finding("aaaaaaaaaaaa"))
    check("First upsert returns True, second returns False", first is True and second is False,
          f"{first}, {second}")
    check("Only one finding row stored", db.row_counts()["threat_findings"] == 1)

    # 2. block then unblock: empty set, 2 rows kept
    fresh_db("block_unblock")
    db.append_geofence_event("block", "ru", ["203.0.113.5"], "GT-RU", False, "netsh ...", "test")
    db.append_geofence_event("unblock", "RU", [], "GT-RU", False, "netsh ...", "test")
    regions = db.get_blocked_regions()
    rows = db.row_counts()["geofence_log"]
    check("Block then unblock leaves no blocked regions", regions == [], str(regions))
    check("Block then unblock keeps 2 rows in geofence_log", rows == 2, f"{rows} rows")

    # 3. two blocks, one unblock: one region left
    fresh_db("two_blocks")
    db.append_geofence_event("block", "RU", [], "GT-RU", False, None, None)
    db.append_geofence_event("block", "CN", [], "GT-CN", False, None, None)
    db.append_geofence_event("unblock", "RU", [], "GT-RU", False, None, None)
    regions = db.get_blocked_regions()
    check("Two blocks and one unblock leaves one region", regions == ["CN"], str(regions))

    # 4. purge keeps active block state
    fresh_db("purge")
    old = "2020-01-01T00:00:00+00:00"
    upd = "UPDATE geofence_log SET ts = ? WHERE id = ?"
    ru = db.append_geofence_event("block", "RU", [], "GT-RU", False, None, None)
    cn1 = db.append_geofence_event("block", "CN", [], "GT-CN", False, None, None)
    cn2 = db.append_geofence_event("unblock", "CN", [], "GT-CN", False, None, None)
    kp = db.append_geofence_event("block", "KP", [], "GT-KP", False, None, None)
    for rid in (ru, cn1, cn2):
        set_ts(upd, rid, old)
    db.upsert_finding(finding("bbbbbbbbbbbb"))
    db._db().execute("UPDATE threat_findings SET last_seen = ? WHERE conn_id = ?", (old, "bbbbbbbbbbbb"))
    db._db().commit()
    before = db.get_blocked_regions()
    removed = db.purge_older_than(7)
    after = db.get_blocked_regions()
    check("Purge keeps active blocked regions unchanged", before == after == ["KP", "RU"], f"{before} -> {after}")
    check("Purge removed the old, inactive geofence rows", removed["geofence_log"] == 2, str(removed))
    check("Purge removed the old finding", removed["threat_findings"] == 1, str(removed))

    # 5. raw paths never stored
    fresh_db("privacy")
    secret = r"C:\Users\secretname\AppData\Local\Temp\evil.exe"
    db.upsert_finding(finding("cccccccccccc", raw_exe=secret, exe=secret,
                              cmdline=f"{secret} --steal", cmdline_redacted=f"{secret} --steal"))
    text = all_rows_text()
    check("raw_exe / exe / cmdline are not stored", "secretname" not in text and "evil.exe --steal" not in text)

    # 6. audit feed is path-free and newest first
    db.append_geofence_event("block", "RU", [], "GT-RU", False, None, None)
    events = db.get_audit_events(50)
    msgs = json.dumps(events)
    check("Audit feed has events of expected types",
          {"threat_detected", "geofence_block"} <= {e["type"] for e in events}, str([e["type"] for e in events]))
    check("Audit messages contain no paths", ":\\\\" not in msgs and "secretname" not in msgs)
    check("Audit feed sorted newest first", [e["ts"] for e in events] == sorted([e["ts"] for e in events], reverse=True))
finally:
    db.close()
    shutil.rmtree(TMP_DIR, ignore_errors=True)

passed = sum(results)
print(f"\n{passed}/{len(results)} passed" + ("" if passed == len(results) else "  <-- FAILURES"))
sys.exit(0 if passed == len(results) else 1)
