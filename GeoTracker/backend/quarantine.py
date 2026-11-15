"""Quarantine request handling. The client sends only a conn_id or manifest_id; the server looks up everything else.

Quarantine: lookup, protected check, simulated dry-run, then for real connections: target
re-verification, SHA-256 fingerprint, stop the process (and unprotected children), and move
the file to the quarantine folder with a manifest row.
Restore: integrity-check the hash, refuse protected destinations and overwrites, move back.
"""
import hashlib
import logging
import os
import shutil
import threading
import time
from datetime import datetime, timezone

import psutil
from pydantic import BaseModel, ConfigDict, Field

import connections
import databricks_export
import db
import events
import quarantine_guards

log = logging.getLogger("geotracker.quarantine")

LOCK_TIMEOUT_SECONDS = 10.0
_lock = threading.Lock()

PROTECTED_MESSAGE = "Safety Override: Cannot delete OS file."
CHANGED_MESSAGE = "Process changed since it was detected. Refresh and try again."
CREATE_TIME_TOLERANCE = 0.01  # seconds
HASH_CHUNK_BYTES = 1024 * 1024
STOP_WAIT_SECONDS = 3.0
MOVE_RETRIES = 3
MOVE_WAIT_SECONDS = 0.5
LOCKED_MESSAGE = ("File is locked by the system. The process was stopped but the "
                  "file was not moved.")


# ---------------------------------------------------------------- verification (read-only)

def _server_lineage():
    """PIDs of this server and all of its ancestors. Raises if it cannot be determined."""
    me = psutil.Process(os.getpid())
    return {os.getpid()} | {p.pid for p in me.parents()}


def check_target(conn):
    """Read-only re-check of a real target. Returns None if it is safe to act on,
    else a short reason code (for server logs and tests; never shown with paths)."""
    pid = conn.get("pid")
    if not isinstance(pid, int) or pid <= 0:
        return "bad_pid"
    if pid == os.getpid():
        return "self"
    try:
        lineage = _server_lineage()
    except Exception:
        return "lineage_unknown"  # fail closed: can't prove it isn't our parent
    if pid in lineage:
        return "server_ancestor"

    captured_ct = conn.get("create_time")
    captured_exe = quarantine_guards.normalize_path(conn.get("raw_exe"))
    if captured_ct is None or captured_exe is None:
        return "capture_incomplete"

    try:
        proc = psutil.Process(pid)
    except psutil.NoSuchProcess:
        return "gone"
    except Exception:
        return "lookup_failed"

    try:
        if abs(proc.create_time() - captured_ct) > CREATE_TIME_TOLERANCE:
            return "create_time_mismatch"
    except psutil.NoSuchProcess:
        return "gone"
    except Exception:
        return "create_time_unreadable"

    try:
        current_exe = quarantine_guards.normalize_path(proc.exe())
    except psutil.NoSuchProcess:
        return "gone"
    except Exception:
        return "exe_unreadable"
    if current_exe is None or current_exe != captured_exe:
        return "exe_mismatch"
    return None


def verify_target(conn):
    """None if the target is unchanged and safe to act on, else (409, body). Never acts."""
    reason = check_target(conn)
    if reason is None:
        return None
    log.info("Target verification failed: conn_id=%s process=%s reason=%s",
             conn.get("id"), conn.get("process_name"), reason)
    return 409, {"ok": False, "message": CHANGED_MESSAGE}


def compute_sha256(path, chunk_size=HASH_CHUNK_BYTES):
    """Hex SHA-256 of a file, read in chunks. Raises OSError if unreadable."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

# ---------------------------------------------------------------- real actions (7D)

def _stop_process(rec):
    """Stop the target and its unprotected children. Returns (ok, message). Never raises, never logs paths."""
    pid = rec["pid"]
    try:
        proc = psutil.Process(pid)
        # Last PID-reuse check immediately before acting.
        if abs(proc.create_time() - rec["create_time"]) > CREATE_TIME_TOLERANCE:
            return False, CHANGED_MESSAGE
        children = proc.children(recursive=True)
    except psutil.NoSuchProcess:
        return True, "Process had already exited."
    except psutil.AccessDenied:
        return False, "Access denied inspecting the process. Run the server as Administrator."

    targets = []
    for ch in children:
        try:
            ch_name = ch.name()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue  # can't identify it: leave it alone
        try:
            ch_exe = ch.exe()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            ch_exe = None  # unknown exe fails closed in is_protected_target
        if quarantine_guards.is_protected_target(ch_exe, ch.pid, ch_name):
            log.info("Skipping protected child: conn_id=%s child=%s", rec.get("id"), ch_name)
            continue
        targets.append(ch)
    targets.append(proc)  # children first, parent last

    for p in targets:
        try:
            p.terminate()
        except psutil.NoSuchProcess:
            pass
        except psutil.AccessDenied:
            if p.pid == pid:
                return False, "Access denied stopping the process. Run the server as Administrator."

    _, alive = psutil.wait_procs(targets, timeout=STOP_WAIT_SECONDS)
    for p in alive:
        try:
            p.kill()
        except psutil.NoSuchProcess:
            pass
        except psutil.AccessDenied:
            if p.pid == pid:
                return False, "Access denied force-stopping the process."

    if alive:
        _, still = psutil.wait_procs(alive, timeout=2.0)
        if any(p.pid == pid for p in still):
            return False, "The process would not stop."
    return True, "Process stopped."


def _move_to_quarantine(raw_exe, sha256):
    """Returns (quarantine_path, error_code). error_code is None on success,
    else one of: 'mkdir', 'missing', 'locked'."""
    try:
        os.makedirs(quarantine_guards.QUARANTINE_DIR, exist_ok=True)
    except OSError:
        return None, "mkdir"

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dest = os.path.join(quarantine_guards.QUARANTINE_DIR, f"{stamp}_{sha256[:8]}.quar")
    n = 1
    while os.path.exists(dest):  # never overwrite an earlier quarantine
        dest = os.path.join(quarantine_guards.QUARANTINE_DIR, f"{stamp}_{sha256[:8]}_{n}.quar")
        n += 1

    for attempt in range(MOVE_RETRIES):
        try:
            shutil.move(raw_exe, dest)
            return dest, None
        except FileNotFoundError:
            return None, "missing"
        except OSError:  # PermissionError is a subclass; Windows holds locks briefly after a kill
            if attempt < MOVE_RETRIES - 1:
                time.sleep(MOVE_WAIT_SECONDS)
    return None, "locked"

# ---------------------------------------------------------------- restore (7E)

RESTORE_INVALID_QPATH_MESSAGE = "Safety Override: Quarantine path is invalid."
RESTORE_PROTECTED_MESSAGE = "Safety Override: Cannot restore into a protected OS location."
RESTORE_EXISTS_MESSAGE = "A file already exists at the original location."


def _inside_quarantine_dir(path):
    """True only if path resolves (realpath, case-folded) strictly inside QUARANTINE_DIR.
    Guards against a tampered DB row or a link pointing out of the folder."""
    p = quarantine_guards.normalize_path(path)
    base = quarantine_guards.normalize_path(quarantine_guards.QUARANTINE_DIR)
    if p is None or base is None:
        return False
    return p.startswith(base.rstrip("\\") + "\\")


# ---------------------------------------------------------------- live op events
# The op currently running under _lock (only one quarantine/restore runs at a time).
_op = None


def _s(step_name, message, status="running", data=None, is_simulated=None):
    events.step(_op, step_name, message, status, data, is_simulated)


def _fail(result, step_name):
    """Report a refusal/failure as one failed step with the exact response message; pass it through."""
    status, body = result
    _s(step_name, body.get("message"), "failed")
    return result


def _run_op(kind, target, fn, *args):
    """Start an op, run fn under it, end it, add op_id to the body, emit connections_changed on success."""
    global _op
    _op = events.start_op(kind, target)
    try:
        status, body = fn(*args)
    except Exception:
        log.exception("%s failed unexpectedly", kind)
        status, body = 500, {"ok": False, "message": "Unexpected error. See server log."}
    ok = bool(body.get("ok"))
    data = {k: body[k] for k in ("manifest_id", "sha256_short") if k in body}
    events.end_op(_op, ok, body.get("message"), data or None,
                  is_simulated=body["simulated"] if "simulated" in body else None)
    body["op_id"] = _op
    if ok:
        events.emit_connections_changed(kind)
    _op = None
    return status, body


def _restore(manifest_id):
    # Called with _lock held; re-reading here means a double-click cannot restore twice.
    # Private paths are server-side only: never returned, logged, or put in audit messages.
    _s("verifying record", "Checking the quarantine record.")
    rec = db.get_quarantine_record(manifest_id, include_private=True)

    # a. record exists
    if rec is None:
        return _fail((404, {"ok": False, "message": "Quarantine record not found."}), "verifying record")
    # b. simulated
    if rec.get("is_simulated"):
        _s("verifying record", "Simulated threat: nothing to restore.", "failed", is_simulated=True)
        return 400, {"ok": False, "message": "Simulated threat: nothing to restore."}
    # c. status
    if rec.get("status") != "quarantined":
        return _fail((409, {"ok": False, "message": f"Not in quarantine (status: {rec.get('status')})."}),
                     "verifying record")
    if rec.get("deleted_at"):
        return _fail((409, {"ok": False, "message": DELETED_MESSAGE}), "verifying record")

    name = rec.get("process_name")
    original = rec.get("original_path_private")
    file_name = os.path.basename(original) if original else (name or "unknown")

    # d. quarantine file must resolve inside the quarantine folder, and exist
    qpath = rec.get("quarantine_path")
    if not qpath or not _inside_quarantine_dir(qpath):
        log.warning("Restore refused (quarantine path invalid): manifest_id=%s", manifest_id)
        return _fail((403, {"ok": False, "code": "PROTECTED", "message": RESTORE_INVALID_QPATH_MESSAGE}),
                     "verifying record")
    qreal = os.path.realpath(qpath)
    if not os.path.isfile(qreal):
        return _fail((409, {"ok": False, "message": "Quarantined file is missing."}), "verifying record")
    _s("verifying record", "Quarantine record is valid.", "ok")

    # e. integrity: must be byte-identical to what was quarantined; on mismatch leave it in place
    _s("checking hash", "Checking the file has not changed in quarantine.")
    try:
        current = compute_sha256(qreal)
    except OSError:
        return _fail((409, {"ok": False, "message": "Quarantined file is missing."}), "checking hash")
    if current != rec.get("sha256"):
        log.warning("Restore refused (hash mismatch): manifest_id=%s process=%s", manifest_id, name)
        db.append_audit_event("quarantine_integrity", "high",
                              f"Restore blocked: {file_name} changed while in quarantine", str(manifest_id))
        return _fail((409, {"ok": False, "message": "File changed while in quarantine."}), "checking hash")
    _s("checking hash", "Hash matches.", "ok", {"sha8": current[:8]})

    # f. destination must not be protected (is_under_protected fails closed on empty/unknown)
    _s("moving back", "Moving the file back to its original location.")
    if quarantine_guards.is_under_protected(original):
        log.info("Restore refused (protected destination): manifest_id=%s process=%s", manifest_id, name)
        return _fail((403, {"ok": False, "code": "PROTECTED", "message": RESTORE_PROTECTED_MESSAGE}),
                     "moving back")
    target = os.path.realpath(original)

    # g. parent folder must still exist; folders are never created
    if not os.path.isdir(os.path.dirname(target)):
        return _fail((409, {"ok": False, "message": "Original folder no longer exists."}), "moving back")

    # h. never overwrite
    if os.path.lexists(target):
        return _fail((409, {"ok": False, "message": RESTORE_EXISTS_MESSAGE}), "moving back")

    # os.rename fails on Windows if the target exists, closing the race window that
    # shutil.move's copy fallback would leave open.
    try:
        os.rename(qreal, target)
    except FileExistsError:
        return _fail((409, {"ok": False, "message": RESTORE_EXISTS_MESSAGE}), "moving back")
    except OSError:
        log.warning("Restore move failed: manifest_id=%s process=%s", manifest_id, name)
        return _fail((500, {"ok": False, "message": "Restore failed: could not move file."}), "moving back")
    _s("moving back", "File moved back.", "ok")
    back = os.path.isfile(target) and not os.path.exists(qreal)
    _s("verified", "File is back at its original location." if back else "Could not confirm the file is back.",
       "ok" if back else "failed")

    # 7D only moves the file (shutil.move); it sets no attributes or ACLs, so there is nothing to undo.

    try:
        if compute_sha256(target) != rec.get("sha256"):
            log.warning("Restored file hash mismatch after move: manifest_id=%s", manifest_id)
    except OSError:
        log.warning("Could not re-hash restored file: manifest_id=%s", manifest_id)

    if not db.mark_quarantine_restored(manifest_id, file_name):
        log.error("File restored but manifest update failed: manifest_id=%s", manifest_id)
    log.info("Restored: manifest_id=%s process=%s sha256=%s", manifest_id, name, current[:8])
    return 200, {
        "ok": True,
        "message": "Restored to original location. Not relaunched.",
        "manifest_id": manifest_id,
        "file_name": file_name,
        "restored_to": rec.get("original_path_redacted") or quarantine_guards.redact_user_path(original),
        "sha256_short": current[:8],
    }


def restore_quarantined(manifest_id):
    """Returns (http_status, body). Never raises. Shares the quarantine lock."""
    if not _lock.acquire(timeout=LOCK_TIMEOUT_SECONDS):
        return 409, {"ok": False, "message": "Another quarantine action is in progress. Try again.",
                     "op_id": None}
    try:
        return _run_op("restore", {"manifest_id": manifest_id}, _restore, manifest_id)
    except Exception:
        log.exception("Restore failed unexpectedly for manifest_id=%s", manifest_id)
        return 500, {"ok": False, "message": "Unexpected error. See server log.", "op_id": None}
    finally:
        _lock.release()


DELETED_MESSAGE = "File was permanently deleted from quarantine."


def _delete(manifest_id):
    """Permanently delete a quarantined file. Only files inside the quarantine folder, for real,
    still-quarantined records. Afterwards the program's quarantine record and threat findings are removed
    from the local database (an audit event remains) and it is no longer queued for Databricks export."""
    _s("verifying record", "Checking the quarantine record.")
    rec = db.get_quarantine_record(manifest_id, include_private=True)
    if rec is None:
        return _fail((404, {"ok": False, "message": "Quarantine record not found."}), "verifying record")
    if rec.get("is_simulated"):
        _s("verifying record", "Simulated threat: nothing to delete.", "failed", is_simulated=True)
        return 400, {"ok": False, "message": "Simulated threat: nothing to delete."}
    if rec.get("status") != "quarantined":
        return _fail((409, {"ok": False, "message": f"Not in quarantine (status: {rec.get('status')})."}),
                     "verifying record")
    if rec.get("deleted_at"):
        return _fail((409, {"ok": False, "message": DELETED_MESSAGE}), "verifying record")

    original = rec.get("original_path_private")
    file_name = os.path.basename(original) if original else (rec.get("process_name") or "unknown")
    qpath = rec.get("quarantine_path")
    if not qpath or not _inside_quarantine_dir(qpath):  # only ever delete inside the quarantine folder
        log.warning("Delete refused (quarantine path invalid): manifest_id=%s", manifest_id)
        return _fail((403, {"ok": False, "code": "PROTECTED", "message": RESTORE_INVALID_QPATH_MESSAGE}),
                     "verifying record")
    qreal = os.path.realpath(qpath)
    if not os.path.isfile(qreal):
        return _fail((409, {"ok": False, "message": "Quarantined file is missing."}), "verifying record")
    _s("verifying record", "Quarantine record is valid.", "ok")

    _s("deleting file", "Permanently deleting the quarantined file.")
    try:
        os.remove(qreal)
    except OSError:
        log.warning("Delete failed: manifest_id=%s", manifest_id)
        return _fail((500, {"ok": False, "message": "Delete failed: could not remove file."}), "deleting file")
    gone = not os.path.exists(qreal)
    _s("verified gone", "The quarantined file is gone." if gone else "Could not confirm the file is gone.",
       "ok" if gone else "failed")
    if not gone:
        return 500, {"ok": False, "message": "Delete failed: could not remove file."}

    _s("clearing records", "Removing this program from the local database.")
    removed = db.mark_quarantine_deleted(manifest_id, file_name)
    if removed is None:
        log.error("File deleted but local records were not cleared: manifest_id=%s", manifest_id)
        _s("clearing records", "File deleted, but its local records could not be cleared.", "failed")
    else:
        _s("clearing records", f"Removed {removed['findings']} finding(s) and {removed['manifest']} quarantine "
           "record(s).", "ok", removed)
    try:
        databricks_export.forget_process(rec.get("process_name"))
    except Exception:
        log.exception("Could not drop deleted program from the export queue")
    log.info("Deleted from quarantine: manifest_id=%s", manifest_id)
    return 200, {"ok": True, "message": "Permanently deleted from quarantine.",
                 "manifest_id": manifest_id, "file_name": file_name}


def delete_quarantined(manifest_id):
    """Returns (http_status, body). Never raises. Shares the quarantine lock."""
    if not _lock.acquire(timeout=LOCK_TIMEOUT_SECONDS):
        return 409, {"ok": False, "message": "Another quarantine action is in progress. Try again.",
                     "op_id": None}
    try:
        return _run_op("delete_quarantine", {"manifest_id": manifest_id}, _delete, manifest_id)
    except Exception:
        log.exception("Delete failed unexpectedly for manifest_id=%s", manifest_id)
        return 500, {"ok": False, "message": "Unexpected error. See server log.", "op_id": None}
    finally:
        _lock.release()


class RestoreRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    manifest_id: int = Field(ge=1)

class QuarantineRequest(BaseModel):
    # extra="forbid": a client that sends pid, path, etc. gets a 422, never a target of its choosing.
    model_config = ConfigDict(extra="forbid")
    conn_id: str = Field(pattern=r"^[0-9a-f]{12}$")


def quarantine_connection(conn_id):
    """Returns (http_status, body). Never raises. Never logs raw paths."""
    if not _lock.acquire(timeout=LOCK_TIMEOUT_SECONDS):
        return 409, {"ok": False, "message": "Another quarantine is in progress. Try again.", "op_id": None}
    try:
        return _run_op("quarantine", {"conn_id": conn_id}, _quarantine, conn_id)
    except Exception:
        log.exception("Quarantine failed unexpectedly for conn_id=%s", conn_id)
        return 500, {"ok": False, "message": "Unexpected error. See server log.", "op_id": None}
    finally:
        _lock.release()


def _quarantine(conn_id):
    # 1. Server-side lookup. The client never names a PID or a path.
    _s("verifying target", "Checking the connection and its process.")
    rec = connections.get_internal_connection(conn_id)
    if rec is None:
        return _fail((404, {"ok": False, "message": "Connection not found or already closed."}), "verifying target")

    pid = rec.get("pid")
    name = rec.get("process_name")
    raw_exe = rec.get("raw_exe")  # server-side only: never returned or logged

    # 2. Protected check first, so simulated-but-protected (rundll32) still shows the lock.
    #    is_protected_target fails closed when raw_exe is None.
    if quarantine_guards.is_protected_target(raw_exe, pid, name):
        log.info("Quarantine refused (protected): conn_id=%s process=%s", conn_id, name)
        _s("verifying target", PROTECTED_MESSAGE, "failed", is_simulated=bool(rec.get("is_simulated")))
        return 403, {"ok": False, "code": "PROTECTED", "message": PROTECTED_MESSAGE}

    # 3. Simulated: record a dry run, touch nothing.
    if rec.get("is_simulated"):
        manifest_id = db.add_quarantine_record(
            pid=pid,
            process_name=name,
            original_path_redacted=quarantine_guards.redact_user_path(raw_exe),
            original_path_private=None,  # simulated: there is no real file to restore
            quarantine_path=None,
            sha256=None,
            status="dry_run",
            is_simulated=True,
            note="Simulated quarantine; no files were touched.",
        )
        log.info("Simulated quarantine: conn_id=%s process=%s manifest_id=%s", conn_id, name, manifest_id)
        _s("verifying target", "Simulated quarantine: no files were touched.", "ok", is_simulated=True)
        return 200, {
            "ok": True,
            "simulated": True,
            "message": "Simulated quarantine: no files were touched.",
            "manifest_id": manifest_id,
        }

    # 4. Real, unprotected: re-verify and fingerprint before acting.
    failure = verify_target(rec)
    if failure is not None:
        return _fail(failure, "verifying target")
    _s("verifying target", "Target verified.", "ok")
    _s("hashing", "Fingerprinting the program file.")
    try:
        sha256 = compute_sha256(raw_exe)
    except OSError:
        log.info("Could not read file to hash: conn_id=%s process=%s", conn_id, name)
        return _fail((409, {"ok": False, "message": "Could not read the program file to fingerprint it."}), "hashing")
    _s("hashing", "Fingerprint recorded.", "ok", {"sha8": sha256[:8]})

    # 5. Real flow: stop the process, then move the file (a running exe is locked, so this order matters).
    _s("stopping process", "Stopping the process.")
    ok, msg = _stop_process(rec)
    if not ok:
        log.info("Stop failed: conn_id=%s process=%s", conn_id, name)
        return _fail(((409 if msg == CHANGED_MESSAGE else 500), {"ok": False, "message": msg}), "stopping process")
    _s("process stopped", msg, "ok")

    _s("moving to quarantine", "Moving the program file to quarantine.")
    qpath, err = _move_to_quarantine(raw_exe, sha256)
    if err is not None:
        _s("moving to quarantine", LOCKED_MESSAGE, "failed")
        # No silent partial state: the process is dead, so record exactly what happened.
        manifest_id = db.add_quarantine_record(
            pid=pid,
            process_name=name,
            original_path_redacted=quarantine_guards.redact_user_path(raw_exe),
            original_path_private=raw_exe,
            quarantine_path=None,
            sha256=sha256,
            status="dry_run",
            is_simulated=False,
            note=f"PARTIAL: process stopped, file NOT moved (reason: {err}).",
        )
        log.warning("Partial quarantine: conn_id=%s process=%s reason=%s manifest_id=%s",
                    conn_id, name, err, manifest_id)
        return 500, {"ok": False, "message": LOCKED_MESSAGE, "manifest_id": manifest_id}

    _s("moving to quarantine", "File moved.", "ok")
    in_place = os.path.isfile(qpath) and not os.path.exists(raw_exe)
    _s("verified", "Original is gone and the quarantined copy is present." if in_place
       else "Could not confirm the file move.", "ok" if in_place else "failed")
    manifest_id = db.add_quarantine_record(
        pid=pid,
        process_name=name,
        original_path_redacted=quarantine_guards.redact_user_path(raw_exe),
        original_path_private=raw_exe,  # needed for restore; never returned by any API
        quarantine_path=qpath,
        sha256=sha256,
        status="quarantined",
        is_simulated=False,
        note="Process stopped and file moved to quarantine.",
    )
    log.info("Quarantined: conn_id=%s process=%s sha256=%s manifest_id=%s",
             conn_id, name, sha256[:8], manifest_id)
    return 200, {
        "ok": True,
        "simulated": False,
        "message": "Quarantined and stopped.",
        "manifest_id": manifest_id,
        "sha256_short": sha256[:8],
    }
