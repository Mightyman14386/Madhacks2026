"""Plain-script tests for quarantine_guards.py. Pure checks only: no processes or files are touched.

Run from backend/:  python test_quarantine_guards.py
"""
import json
import os
import shutil
import sys

import connections
import quarantine_guards as g

results = []


def check(label, actual, expected):
    ok = actual == expected
    results.append(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] {label}  (got {actual}, expected {expected})")


CMD = r"C:\Windows\System32\cmd.exe"
TEMP_EXE = os.path.join(os.environ.get("TEMP", r"C:\Users\someone\AppData\Local\Temp"), "test_agent.exe")

# Path normalization / bypass attempts
check("C:\\WINDOWS (upper case) is protected", g.is_under_protected(r"C:\WINDOWS\System32\cmd.exe"), True)
check("c:\\windows (lower case) is protected", g.is_under_protected(r"c:\windows\system32\cmd.exe"), True)
check("Upper and lower case normalize identically",
      g.normalize_path(r"C:\WINDOWS\System32\CMD.EXE") == g.normalize_path(r"c:\windows\system32\cmd.exe"), True)
check("..\\ traversal (System32\\..\\System32) is protected",
      g.is_under_protected(r"C:\Windows\System32\..\System32\cmd.exe"), True)
check("..\\ escaping out of a safe folder into Windows is protected",
      g.is_under_protected(r"C:\Users\someone\..\..\Windows\System32\cmd.exe"), True)
check("Trailing dot on folder (C:\\Windows.\\...) is protected",
      g.is_under_protected(r"C:\Windows.\System32\cmd.exe"), True)
check("Trailing space on folder (C:\\Windows \\...) is protected",
      g.is_under_protected("C:\\Windows \\System32\\cmd.exe"), True)
check("Trailing dots/spaces on file name normalize away",
      g.normalize_path(CMD + ". .") == g.normalize_path(CMD), True)
check("Mixed slashes (C:/Windows\\System32/cmd.exe) are protected",
      g.is_under_protected(r"C:/Windows\System32/cmd.exe"), True)
check("Doubled slashes (C:\\\\Windows\\\\\\System32) are protected",
      g.is_under_protected("C:\\\\Windows\\\\\\System32\\cmd.exe"), True)
check("Program Files is protected", g.is_under_protected(r"C:\Program Files\App\app.exe"), True)
check("C:\\ProgramData\\Microsoft is protected", g.is_under_protected(r"C:\ProgramData\Microsoft\x.exe"), True)

# Boundary checks: prefixes that are NOT inside a protected folder
check("C:\\Windows2 is NOT protected", g.is_under_protected(r"C:\Windows2\evil.exe"), False)
check("C:\\Program Files (x86)Evil is NOT protected",
      g.is_under_protected(r"C:\Program Files (x86)Evil\a.exe"), False)
check("C:\\ProgramData\\Other is NOT protected", g.is_under_protected(r"C:\ProgramData\Other\a.exe"), False)
check("Exe in %TEMP% is NOT protected", g.is_under_protected(TEMP_EXE), False)
check("Exe in %TEMP% is NOT a protected target", g.is_protected_target(TEMP_EXE, 12345, "test_agent.exe"), False)

# Fail closed
check("None path fails closed", g.is_under_protected(None), True)
check("Empty path fails closed", g.is_under_protected(""), True)
check("normalize_path(None) is None", g.normalize_path(None), None)
check("None raw_exe target fails closed", g.is_protected_target(None, 12345, "evil.exe"), True)

# PID and name blocklists (exe outside protected paths, so only the blocklist can protect)
check("PID 0 is protected", g.is_protected_target(TEMP_EXE, 0, "x.exe"), True)
check("PID 4 is protected", g.is_protected_target(TEMP_EXE, 4, "x.exe"), True)
check("Own PID is protected", g.is_protected_target(TEMP_EXE, os.getpid(), "x.exe"), True)
check("explorer.exe is protected", g.is_protected_target(TEMP_EXE, 12345, "explorer.exe"), True)
check("svchost.exe is protected (any case)", g.is_protected_target(TEMP_EXE, 12345, "SvcHost.EXE"), True)

# Redaction and single source of truth
red = g.redact_user_path(r"C:\Users\someone\AppData\Local\Temp\a.exe")
check("redact_user_path replaces the username", red, r"C:\Users\<user>\AppData\Local\Temp\a.exe")
check("connections.is_protected_process delegates (TEMP exe)",
      connections.is_protected_process(TEMP_EXE, 12345, "test_agent.exe"), False)
check("connections.is_protected_process delegates (cmd.exe)",
      connections.is_protected_process(CMD, 12345, "cmd.exe"), True)
check("QUARANTINE_DIR is outside every protected path", g.is_under_protected(g.QUARANTINE_DIR), False)

# ---------------------------------------------------------------- verify_target (psutil mocked)
import hashlib
import tempfile
from unittest import mock

import psutil

import quarantine

OWN = os.getpid()
PARENT, GRANDPARENT, TARGET = 900001, 900002, 900003
EXE = r"C:\Users\someone\AppData\Local\Temp\test_agent.exe"


class FakeProc:
    def __init__(self, pid, create_time=1000.0, exe=EXE, parents=(), exe_error=None, ct_error=None):
        self.pid = pid
        self._ct, self._exe, self._parents = create_time, exe, parents
        self._exe_error, self._ct_error = exe_error, ct_error

    def create_time(self):
        if self._ct_error:
            raise self._ct_error
        return self._ct

    def exe(self):
        if self._exe_error:
            raise self._exe_error
        return self._exe

    def parents(self):
        return list(self._parents)


def fake_table(target=None, server_parents_error=False):
    table = {OWN: FakeProc(OWN, parents=[FakeProc(PARENT), FakeProc(GRANDPARENT)])}
    if server_parents_error:
        table[OWN].parents = mock.Mock(side_effect=psutil.AccessDenied(OWN))
    for pid in (PARENT, GRANDPARENT):
        table[pid] = FakeProc(pid)
    if target is not None:
        table[target.pid] = target

    def factory(pid):
        if pid not in table:
            raise psutil.NoSuchProcess(pid)
        return table[pid]
    return factory


def conn_for(pid=TARGET, create_time=1000.0, raw_exe=EXE):
    return {"id": "abcdefabcdef", "pid": pid, "process_name": "test_agent.exe",
            "create_time": create_time, "raw_exe": raw_exe}


def reason(conn, **table_kwargs):
    with mock.patch("quarantine.psutil.Process", side_effect=fake_table(**table_kwargs)):
        return quarantine.check_target(conn)


check("verify: unchanged process passes", reason(conn_for(), target=FakeProc(TARGET)), None)
check("verify: exe compare is normalized (case and slashes)",
      reason(conn_for(raw_exe=EXE.upper().replace("\\", "/")), target=FakeProc(TARGET)), None)
check("verify: PID no longer exists", reason(conn_for()), "gone")
check("verify: create_time changed (PID reused)",
      reason(conn_for(), target=FakeProc(TARGET, create_time=2000.0)), "create_time_mismatch")
check("verify: exe path changed",
      reason(conn_for(), target=FakeProc(TARGET, exe=r"C:\Other\thing.exe")), "exe_mismatch")
check("verify: exe unreadable (AccessDenied) fails closed",
      reason(conn_for(), target=FakeProc(TARGET, exe_error=psutil.AccessDenied(TARGET))), "exe_unreadable")
check("verify: process exits during check",
      reason(conn_for(), target=FakeProc(TARGET, ct_error=psutil.NoSuchProcess(TARGET))), "gone")
check("verify: missing captured create_time fails closed",
      reason(conn_for(create_time=None), target=FakeProc(TARGET)), "capture_incomplete")
check("verify: missing raw_exe fails closed",
      reason(conn_for(raw_exe=None), target=FakeProc(TARGET)), "capture_incomplete")
check("verify: server's own PID refused", reason(conn_for(pid=OWN)), "self")
check("verify: server's parent refused", reason(conn_for(pid=PARENT)), "server_ancestor")
check("verify: server's grandparent refused", reason(conn_for(pid=GRANDPARENT)), "server_ancestor")
check("verify: unknown server lineage fails closed",
      reason(conn_for(), target=FakeProc(TARGET), server_parents_error=True), "lineage_unknown")
check("verify: negative (simulated-style) PID refused", reason(conn_for(pid=-1001)), "bad_pid")

with mock.patch("quarantine.psutil.Process", side_effect=fake_table()):
    status_body = quarantine.verify_target(conn_for())
check("verify_target returns 409 with the exact message",
      status_body, (409, {"ok": False, "message": "Process changed since it was detected. Refresh and try again."}))
with mock.patch("quarantine.psutil.Process", side_effect=fake_table(target=FakeProc(TARGET))):
    check("verify_target returns None when unchanged", quarantine.verify_target(conn_for()), None)

# compute_sha256 on a temp data file (multi-chunk)
with tempfile.TemporaryDirectory() as d:
    p = os.path.join(d, "sample.bin")
    data = bytes(range(256)) * 5000  # 1.28 MB, deterministic
    with open(p, "wb") as f:
        f.write(data)
    check("compute_sha256 matches hashlib (small chunks)",
          quarantine.compute_sha256(p, chunk_size=4096), hashlib.sha256(data).hexdigest())
    check("compute_sha256 matches hashlib (default chunks)",
          quarantine.compute_sha256(p), hashlib.sha256(data).hexdigest())

# ---------------------------------------------------------------- restore decision checks
# Temp DB + temp folders; QUARANTINE_DIR is patched, so the real C:\GeoTrench is never touched.
import db

RESTORE_ROOT = tempfile.mkdtemp(prefix="geotrench_restore_")
TQ = os.path.join(RESTORE_ROOT, "quarantine")
HOME = os.path.join(RESTORE_ROOT, "home")
OUTSIDE = os.path.join(RESTORE_ROOT, "outside")
for d in (TQ, HOME, OUTSIDE):
    os.makedirs(d)
db.init_db(os.path.join(RESTORE_ROOT, "restore_test.db"))
_seq = [0]


def fake_record(status="quarantined", is_simulated=False, qdir=TQ, original=None,
                stored_hash=None, write_qfile=True):
    """Create a quarantined file plus a manifest row pointing at it. Returns (manifest_id, qpath, original)."""
    _seq[0] += 1
    data = f"geotrench restore test {_seq[0]}".encode()
    qpath = os.path.join(qdir, f"20260101T000000Z_{_seq[0]:08d}.quar")
    if write_qfile:
        with open(qpath, "wb") as f:
            f.write(data)
    original = original or os.path.join(HOME, f"agent_{_seq[0]}.exe")
    mid = db.add_quarantine_record(
        pid=4242, process_name=os.path.basename(original),
        original_path_redacted=g.redact_user_path(original), original_path_private=original,
        quarantine_path=qpath, sha256=stored_hash or hashlib.sha256(data).hexdigest(),
        status=status, is_simulated=is_simulated, note="test",
    )
    return mid, qpath, original


def restore(mid):
    with mock.patch.object(g, "QUARANTINE_DIR", TQ):
        return quarantine.restore_quarantined(mid)


def check_restore(label, mid, status, message):
    code, body = restore(mid)
    check(label, (code, body.get("message")), (status, message))
    return code, body


try:
    check_restore("restore: missing record", 999999, 404, "Quarantine record not found.")

    mid, _, _ = fake_record(is_simulated=True)
    check_restore("restore: simulated record", mid, 400, "Simulated threat: nothing to restore.")

    mid, _, _ = fake_record(status="dry_run")
    check_restore("restore: wrong status", mid, 409, "Not in quarantine (status: dry_run).")

    mid, qp, _ = fake_record(qdir=OUTSIDE)
    check_restore("restore: quarantine path outside the quarantine folder", mid, 403,
                  "Safety Override: Quarantine path is invalid.")
    check("restore: file outside quarantine folder left in place", os.path.isfile(qp), True)

    mid, _, _ = fake_record(write_qfile=False)
    check_restore("restore: quarantined file missing", mid, 409, "Quarantined file is missing.")

    mid, qp, orig = fake_record(stored_hash="0" * 64)
    check_restore("restore: hash mismatch", mid, 409, "File changed while in quarantine.")
    check("restore: tampered file left in quarantine", (os.path.isfile(qp), os.path.exists(orig)), (True, False))
    check("restore: hash mismatch wrote an audit event",
          any(e["type"] == "quarantine_integrity" and e["ref_id"] == str(mid) for e in db.get_audit_events(100)), True)

    mid, qp, _ = fake_record(original=r"C:\Windows\System32\test_agent.exe")
    check_restore("restore: protected target", mid, 403,
                  "Safety Override: Cannot restore into a protected OS location.")
    check("restore: protected-target file left in quarantine", os.path.isfile(qp), True)

    mid, qp, orig = fake_record()
    with open(orig, "wb") as f:
        f.write(b"someone else's file")
    check_restore("restore: existing target is never overwritten", mid, 409,
                  "A file already exists at the original location.")
    with open(orig, "rb") as f:
        check("restore: existing target content unchanged", f.read(), b"someone else's file")
    check("restore: existing-target case left file in quarantine", os.path.isfile(qp), True)

    mid, qp, _ = fake_record(original=os.path.join(HOME, "no_such_folder", "agent.exe"))
    check_restore("restore: missing parent folder", mid, 409, "Original folder no longer exists.")
    check("restore: parent folder was not created", os.path.isdir(os.path.join(HOME, "no_such_folder")), False)

    # Happy path, then a double restore.
    mid, qp, orig = fake_record()
    code, body = check_restore("restore: success", mid, 200, "Restored to original location. Not relaunched.")
    check("restore: file moved back, quarantine copy gone", (os.path.isfile(orig), os.path.exists(qp)), (True, False))
    check("restore: response has no private paths",
          RESTORE_ROOT.casefold() in json.dumps(body).casefold() or "quarantine_path" in body
          or "original_path_private" in body, False)
    check("restore: response fields", sorted(body), sorted(
        ["ok", "message", "manifest_id", "file_name", "restored_to", "sha256_short", "op_id"]))
    rec = db.get_quarantine_record(mid)
    check("restore: manifest marked restored with restored_at", (rec["status"], bool(rec["restored_at"])),
          ("restored", True))
    listed = next(r for r in db.list_quarantine_records() if r["id"] == mid)
    check("restore: list shows restored + restored_at, no private fields",
          (listed["status"], bool(listed["restored_at"]),
           "original_path_private" in listed, "quarantine_path" in listed),
          ("restored", True, False, False))
    events = [e for e in db.get_audit_events(100) if e["ref_id"] == str(mid)]
    check("restore: audit has 'Restored <file_name>' and keeps 'Quarantined'",
          ({"quarantine_restore", "quarantine"} <= {e["type"] for e in events},
           any(e["message"] == f"Restored {os.path.basename(orig)}" for e in events)), (True, True))
    check("restore: audit messages contain no paths",
          RESTORE_ROOT.casefold() in json.dumps(events).casefold(), False)
    check_restore("restore: double restore refused", mid, 409, "Not in quarantine (status: restored).")

    # ------------------------------------------------------------ permanent delete from quarantine
    def delete(mid):
        with mock.patch.object(g, "QUARANTINE_DIR", TQ):
            return quarantine.delete_quarantined(mid)

    mid, qp, orig = fake_record()
    name = os.path.basename(orig)
    for i, simulated in ((1, False), (2, False), (3, True)):
        db.upsert_finding({"id": f"dd{i:010d}", "pid": 4242, "process_name": name, "remote_ip": f"1.2.3.{i}",
                           "remote_port": 443, "severity": "medium", "rules_fired": [], "reasons": [],
                           "ancestry": [], "is_simulated": simulated})
    db.upsert_finding({"id": "dd0000000009", "pid": 7, "process_name": "other.exe", "remote_ip": "1.2.3.9",
                       "remote_port": 443, "severity": "low", "rules_fired": [], "reasons": [],
                       "ancestry": [], "is_simulated": False})
    def findings_for(n):
        return db._db().execute("SELECT is_simulated FROM threat_findings WHERE process_name = ?", (n,)).fetchall()
    code, body = delete(mid)
    check("delete: success", (code, body["ok"], body["message"], body["file_name"]),
          (200, True, "Permanently deleted from quarantine.", os.path.basename(orig)))
    check("delete: .quar file removed, original not recreated", (os.path.exists(qp), os.path.exists(orig)), (False, False))
    check("delete: response has no paths", RESTORE_ROOT.casefold() in json.dumps(body).casefold(), False)
    check("delete: quarantine record removed from the local db",
          any(r["id"] == mid for r in db.list_quarantine_records()), False)
    check("delete: real findings for the program removed, simulated + other programs kept",
          ([tuple(r) for r in findings_for(name)], len(findings_for("other.exe"))), ([(1,)], 1))
    check("delete: audit records the deletion",
          any(e["message"] == f"Permanently deleted {name} from quarantine and cleared its local records"
              for e in db.get_audit_events(200)), True)
    check("delete: second delete refused", delete(mid)[1]["message"], "Quarantine record not found.")
    check_restore("delete: restore after delete refused", mid, 404, "Quarantine record not found.")

    mid, qp, _ = fake_record(qdir=OUTSIDE)
    code, body = delete(mid)
    check("delete: path outside quarantine folder refused, file untouched",
          (code, body["message"], os.path.isfile(qp)), (403, "Safety Override: Quarantine path is invalid.", True))
    mid, _, _ = fake_record(is_simulated=True)
    check("delete: simulated record", delete(mid)[:1] + (delete(mid)[1]["message"],), (400, "Simulated threat: nothing to delete."))
    check("delete: missing record", delete(999999)[1]["message"], "Quarantine record not found.")
    mid, _, _ = fake_record(status="restored")
    check("delete: wrong status", delete(mid)[1]["message"], "Not in quarantine (status: restored).")
finally:
    db.close()
    shutil.rmtree(RESTORE_ROOT, ignore_errors=True)

passed = sum(results)
print(f"\n{passed}/{len(results)} passed" + ("" if passed == len(results) else "  <-- FAILURES"))
sys.exit(0 if passed == len(results) else 1)
