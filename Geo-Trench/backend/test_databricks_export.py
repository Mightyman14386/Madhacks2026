"""Plain-script tests for databricks_export.py. No network: the Databricks client is mocked.

Run from backend/:  python test_databricks_export.py
"""
import json
import os
import shutil
import sys
import tempfile
import types
from unittest import mock

# Use the real SDK parameter class if installed; otherwise a stand-in with the same constructor.
try:
    from databricks.sdk.service.sql import StatementParameterListItem  # noqa: F401
except Exception:
    class StatementParameterListItem:
        def __init__(self, name=None, value=None, type=None):
            self.name, self.value, self.type = name, value, type
    for mod in ("databricks", "databricks.sdk", "databricks.sdk.service", "databricks.sdk.service.sql"):
        sys.modules.setdefault(mod, types.ModuleType(mod))
    sys.modules["databricks.sdk.service.sql"].StatementParameterListItem = StatementParameterListItem

import config
import connections
import databricks_export as dx
import db

results = []


def check(label, actual, expected):
    ok = actual == expected
    results.append(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] {label}" + ("" if ok else f"  (got {actual!r}, expected {expected!r})"))


def ok_resp(inserted=None):
    resp = types.SimpleNamespace(status=types.SimpleNamespace(state=types.SimpleNamespace(value="SUCCEEDED")))
    if inserted is not None:
        cols = [types.SimpleNamespace(name="num_affected_rows"), types.SimpleNamespace(name="num_inserted_rows")]
        resp.manifest = types.SimpleNamespace(schema=types.SimpleNamespace(columns=cols))
        resp.result = types.SimpleNamespace(data_array=[[str(inserted), str(inserted)]])
    return resp


class FakeAPI:
    """Accepts every statement; reports no num_inserted_rows."""
    def __init__(self, fail=False):
        self.calls, self.fail = [], fail

    def execute_statement(self, **kw):
        self.calls.append(kw)
        if self.fail:
            raise RuntimeError("secret-token-xyz in SDK error text")
        return ok_resp()


class FakeTable(FakeAPI):
    """Emulates geospatial_incidents + the INSERT ... WHERE NOT EXISTS on (ip, rounded coords, device)."""
    def __init__(self):
        super().__init__()
        self.keys = set()

    def execute_statement(self, **kw):
        self.calls.append(kw)
        by_row, tag = {}, None
        for p in kw["parameters"]:
            if p.name == "device_tag":
                tag = p.value
                continue
            col, idx = p.name.rsplit("_", 1)
            by_row.setdefault(int(idx), {})[col] = float(p.value) if p.type == "DOUBLE" else p.value
        inserted = 0
        for row in by_row.values():
            assert row["description"].endswith(tag), "row description must carry the device tag"
            key = dx.dedupe_key(row) + (tag,)
            if key not in self.keys:
                self.keys.add(key)
                inserted += 1
        return ok_resp(inserted)


def fake_client(api):
    return types.SimpleNamespace(statement_execution=api)


ORIGIN = {"lat": 43.0731, "lng": -89.4012, "name": "Madison, WI"}
FINDING = {
    "id": "abc123abc123", "pid": 4242, "process_name": "payload.exe",
    "remote_ip": "203.0.113.66", "remote_port": 1337,
    "country_code": "CN", "city": "Shenzhen", "lat": 22.5431, "lng": 114.0579,
    "severity": "medium", "reasons": ["Connected over port 1337.", "Started from PowerShell."],
    "is_simulated": False,
    # fields that must never leak into the row:
    "raw_exe": r"C:\Users\secretname\AppData\Local\Temp\payload.exe",
    "exe": r"C:\Users\<user>\AppData\Local\Temp\payload.exe",
    "local_ip": "192.168.1.50", "cmdline_redacted": "payload.exe --x",
    "ancestry": ["explorer.exe", "powershell.exe", "payload.exe"],
}

# ------------------------------------------------------------ mapping
row = dx.to_incident_row(FINDING, ORIGIN)
check("map: columns match geospatial_incidents", sorted(row), sorted(dx.TABLE_COLUMNS))
check("map: src = origin, dest = remote location",
      (row["latitude_src"], row["longitude_src"], row["latitude_dest"], row["longitude_dest"]),
      (43.0731, -89.4012, 22.5431, 114.0579))
check("map: severity and ip", (row["severity"], row["ip"]), ("medium", "203.0.113.66"))
check("map: description",
      row["description"],
      "payload.exe -> 203.0.113.66:1337 (Shenzhen, CN): Connected over port 1337.; Started from PowerShell." + dx.device_tag())
text = json.dumps(row)
check("map: no paths, local IP, cmdline or username", any(s in text for s in ("C:\\", "secretname", "192.168.1.50", "--x")), False)
check("map: simulated suffix", dx.to_incident_row({**FINDING, "is_simulated": True}, ORIGIN)["description"].endswith(" [simulated]" + dx.device_tag()), True)
check("map: safe connection exported too", dx.to_incident_row({**FINDING, "status": "safe", "severity": "low"}, ORIGIN)["severity"], "low")
check("map: no coordinates (anycast/unlocated) skipped", dx.to_incident_row({**FINDING, "lat": None}, ORIGIN), None)
check("map: non-finite coordinate skipped", dx.to_incident_row({**FINDING, "lng": float("nan")}, ORIGIN), None)
check("map: description capped at 4000", len(dx.to_incident_row({**FINDING, "reasons": ["x" * 9000]}, ORIGIN)["description"]), 4000)

# ------------------------------------------------------------ sender
api = FakeAPI()
with mock.patch.object(dx, "_client", fake_client(api)):
    n = dx.insert_incidents([row, {**row, "ip": "203.0.113.67"}])
call = api.calls[0]
check("insert: returns rows inserted (len when not reported)", n, 2)
check("insert: targets warehouse/catalog/schema",
      (call["warehouse_id"], call["catalog"], call["schema"]), (config.DATABRICKS_WAREHOUSE_ID, "workspace", "default"))
check("insert: SQL has named placeholders, no literal values",
      (":latitude_src_0" in call["statement"], ":ip_1" in call["statement"],
       "203.0.113.66" in call["statement"], "payload.exe" in call["statement"]), (True, True, False, False))
check("insert: 7 parameters per row + device tag", len(call["parameters"]), 15)
types_by_name = {p.name: p.type for p in call["parameters"]}
check("insert: coords DOUBLE, text STRING",
      (types_by_name["latitude_dest_0"], types_by_name["severity_0"], types_by_name["ip_1"]), ("DOUBLE", "STRING", "STRING"))
check("insert: empty list -> 0, no call", (dx.insert_incidents([]), len(api.calls)), (0, 1))
stmt = call["statement"]
check("insert: table-side redundancy check (NOT EXISTS on ip + 4 rounded coords)",
      ("WHERE NOT EXISTS" in stmt, "g.ip = v.ip" in stmt,
       all(f"round(g.{c}, 4) = round(v.{c}, 4)" in stmt for c in dx.COORD_COLUMNS)), (True, True, True))
check("insert: VALUES aliased as v(<all 7 columns>)", f"AS v({', '.join(dx.TABLE_COLUMNS)})" in stmt, True)

with mock.patch.object(dx, "_client", fake_client(FakeAPI(fail=True))):
    check("insert: failure returns None, never raises", dx.insert_incidents([row]), None)
check("insert: stored error never contains SDK text", "secret-token" in (dx.export_state()["last_error"] or ""), False)

near = {**row, "latitude_dest": row["latitude_dest"] + 0.00001}   # ~1 m away: same point
far = {**row, "latitude_dest": row["latitude_dest"] + 0.01}       # ~1 km away: different point
other_ip = {**row, "ip": "203.0.113.67"}
uniq, dropped = dx.dedupe_rows([row, dict(row), near, far, other_ip])
check("dedupe: same IP + same/near coords collapsed; other point or IP kept",
      (len(uniq), dropped, uniq[1]["latitude_dest"], uniq[2]["ip"]), (3, 2, far["latitude_dest"], "203.0.113.67"))

table = FakeTable()
table.keys.add(dx.dedupe_key(row) + (dx.device_tag(),))
dx._state["duplicates_skipped"] = 0
with mock.patch.object(dx, "_client", fake_client(table)):
    check("insert: returns num_inserted_rows from Databricks", dx.insert_incidents([row, other_ip]), 1)
check("insert: rows already in the table counted as duplicates_skipped", dx._state["duplicates_skipped"], 1)

# ------------------------------------------------------------ reconcile against a temp DB
TMP = tempfile.mkdtemp(prefix="geotrench_export_")
LOCATED = {"lat": 22.5431, "lng": 114.0579, "country_code": "CN", "country_name": "China", "city": "Shenzhen"}


def fresh(name):
    db.init_db(os.path.join(TMP, f"{name}.db"))
    dx._state.update({"exported": 0, "skipped": 0, "duplicates_skipped": 0, "last_error": None})


def add_finding(i, simulated=False, ip=None):
    db.upsert_finding({**FINDING, "id": f"f{i:011d}", "remote_ip": ip or f"1.0.{i // 200}.{i % 200 + 1}",
                       "is_simulated": simulated})


def stamps():
    return dict(db._db().execute("SELECT conn_id, exported_at FROM threat_findings").fetchall())


def sync(api, simulated=False):
    with mock.patch.object(dx, "_client", fake_client(api)), \
            mock.patch.object(dx.geo, "geolocate", lambda ip: dict(LOCATED)), \
            mock.patch.object(config, "DATABRICKS_EXPORT_SIMULATED", simulated):
        return dx.flush_once()


try:
    with mock.patch.object(config, "DATABRICKS_EXPORT_ENABLED", False):
        check("enqueue: disabled -> no wake", dx.enqueue(FINDING), False)
    with mock.patch.object(config, "DATABRICKS_EXPORT_ENABLED", True):
        dx._wake.clear()
        check("enqueue: enabled -> wakes the worker", (dx.enqueue(FINDING), dx._wake.is_set()), (True, True))
        dx._wake.clear()

    # Full scan: every local finding is offered, in batches; the table inserts what's new.
    fresh("scan")
    for i in range(120):
        add_finding(i)
    check("db: migration added exported_at (all NULL)", set(stamps().values()), {None})
    table = FakeTable()
    check("scan: first pass inserts all 120", sync(table), 120)
    check("scan: batches of 50/50/20", [len(c["parameters"]) // 7 for c in table.calls], [50, 50, 20])
    check("scan: all stamped, pending 0", (all(stamps().values()), dx.export_state()["pending"]), (True, 0))

    table.calls.clear()
    check("re-scan: existing rows not duplicated (0 inserted)", sync(table), 0)
    check("re-scan: still scans every finding", sum(len(c["parameters"]) // 7 for c in table.calls), 120)
    check("re-scan: table still holds 120 unique rows", len(table.keys), 120)

    # Real-environment recovery: table truncated in Databricks -> next pass re-inserts everything.
    table.keys.clear()
    check("truncate: next pass re-inserts all 120", sync(table), 120)

    # Partial deletion: only missing rows come back.
    for key in list(table.keys)[:7]:
        table.keys.discard(key)
    check("partial delete: only the 7 missing rows re-inserted", sync(table), 7)

    # A new finding: only it is inserted.
    add_finding(999, ip="1.2.3.4")
    check("new finding: only the new one inserted", sync(table), 1)

    # Simulated gating.
    fresh("sim")
    add_finding(1)
    add_finding(500, simulated=True, ip="203.0.113.66")
    table = FakeTable()
    check("simulated: excluded by default (only the real one)", sync(table, simulated=False), 1)
    check("simulated: included when allowed (planted location)", sync(table, simulated=True), 1)
    sent = {p.name: p.value for p in table.calls[-1]["parameters"]}
    sim_idx = next(k.rsplit("_", 1)[1] for k, v in sent.items() if v == "203.0.113.66")
    check("simulated: uses planted geo and [simulated] tag",
          (sent[f"latitude_dest_{sim_idx}"], sent[f"description_{sim_idx}"].endswith("[simulated]" + dx.device_tag())), ("22.5431", True))

    # Failure: nothing stamped; next pass retries.
    fresh("fail")
    add_finding(600)
    check("failure: pass inserts 0", sync(FakeAPI(fail=True)), 0)
    check("failure: finding stays unstamped", stamps()["f00000000600"], None)
    check("failure: retried successfully next pass", sync(FakeTable()), 1)

    # Redundancy inside one batch.
    fresh("redundancy")
    for i in range(800, 803):
        add_finding(i, ip="1.0.9.9")
    table = FakeTable()
    check("redundancy: 3 findings, same IP+coords -> 1 row", sync(table), 1)
    check("redundancy: only 1 row offered to the table", len(table.calls[0]["parameters"]) // 7, 1)
    check("redundancy: all 3 stamped", all(stamps()[f"f{i:011d}"] for i in range(800, 803)), True)

    # Unlocatable (e.g. anycast) findings are skipped, never sent.
    fresh("skip")
    add_finding(700, ip="1.1.1.1")
    with mock.patch.object(dx, "_client", fake_client(FakeTable())), \
            mock.patch.object(dx.geo, "geolocate", lambda ip: {"lat": None, "lng": None}):
        check("skip: unlocatable finding not sent", dx.flush_once(), 0)
    check("skip: stamped 'skipped:'", stamps()["f00000000700"].startswith("skipped:"), True)
    # Parity: every located device connection (safe too) is mirrored with identical coordinates.
    fresh("observe")
    dx._observed.clear()
    safe = {"id": "s1", "process_name": "chrome.exe", "remote_ip": "8.8.4.4", "remote_port": 443,
            "city": "Ashburn", "country_code": "US", "lat": 39.0438, "lng": -77.4874,
            "status": "safe", "severity": "low", "reasons": [], "is_simulated": False}
    with mock.patch.object(config, "DATABRICKS_EXPORT_ENABLED", True),             mock.patch.object(config, "DATABRICKS_EXPORT_SIMULATED", False):
        check("observe: safe + located queued, dupes/unlocated/simulated dropped",
              dx.observe_connections([safe, dict(safe, id="s2"), dict(safe, id="s3", lat=None),
                                      dict(safe, id="s4", remote_ip="9.9.9.9", is_simulated=True)], ORIGIN), 1)
    with mock.patch.object(config, "DATABRICKS_EXPORT_ENABLED", False):
        check("observe: disabled -> nothing queued", dx.observe_connections([dict(safe, remote_ip="7.7.7.7")], ORIGIN), 0)
    table = FakeTable()
    check("observe: flushed to the table", sync(table), 1)
    sent = {p.name: p.value for p in table.calls[-1]["parameters"]}
    check("observe: src = device origin, dest = GeoIP point, severity low",
          tuple(float(sent[k + "_0"]) for k in ("latitude_src", "longitude_src", "latitude_dest", "longitude_dest"))
          + (sent["severity_0"],),
          (float(ORIGIN["lat"]), float(ORIGIN["lng"]), 39.0438, -77.4874, "low"))
    check("observe: re-pass does not duplicate", sync(table), 0)
    with mock.patch.object(config, "DEVICE_NAME", "OTHER-LAPTOP"):
        dx._observed.clear()
        with mock.patch.object(config, "DATABRICKS_EXPORT_ENABLED", True):
            dx.observe_connections([safe], ORIGIN)
        check("observe: same route from another device is still added", sync(table), 1)
        check("observe: description tagged with device", table.calls[-1]["parameters"][5].value.endswith(" @OTHER-LAPTOP"), True)
    with mock.patch.object(config, "DATABRICKS_EXPORT_ENABLED", True):
        dx._observed.clear()
        dx.observe_connections([safe, dict(safe, process_name="evil.exe", remote_ip="5.5.5.5")], ORIGIN)
    check("forget: deleted program dropped from export queue, others kept",
          (dx.forget_process("evil.exe"), [r["ip"] for r in dx._observed.values()]), (1, ["8.8.4.4"]))
    dx._observed.clear()
finally:
    db.close()
    shutil.rmtree(TMP, ignore_errors=True)

# ------------------------------------------------------------ first-sight trigger in connections.get_snapshot
seen = []
upserts = iter([True, False, True, False, False, False, False, False, False, False])
with mock.patch.object(db, "upsert_finding", lambda f: next(upserts, False)), \
        mock.patch.object(dx, "enqueue", lambda f: seen.append(f["id"])), \
        mock.patch.object(config, "DEMO_MODE", True):
    connections.get_snapshot()
check("trigger: enqueue called only when upsert_finding returns True", len(seen), 2)

passed = sum(results)
print(f"\n{passed}/{len(results)} passed" + ("" if passed == len(results) else "  <-- FAILURES"))
sys.exit(0 if passed == len(results) else 1)
