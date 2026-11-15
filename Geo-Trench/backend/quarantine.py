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
import db
import quarantine_guards

log = logging.getLogger("geotrench.quarantine")

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


def _restore(manifest_id):
    # Called with _lock held; re-reading here means a double-click cannot restore twice.
    # Private paths are server-side only: never returned, logged, or put in audit messages.
    rec = db.get_quarantine_record(manifest_id, include_private=True)

    # a. record exists
    if rec is None:
        return 404, {"ok": False, "message": "Quarantine record not found."}
    # b. simulated
    if rec.get("is_simulated"):
        return 400, {"ok": False, "message": "Simulated threat: nothing to restore."}
    # c. status
    if rec.get("status") != "quarantined":
        return 409, {"ok": False, "message": f"Not in quarantine (status: {rec.get('status')})."}

    name = rec.get("process_name")
    original = rec.get("original_path_private")
    file_name = os.path.basename(original) if original else (name or "unknown")

    # d. quarantine file must resolve inside the quarantine folder, and exist
    qpath = rec.get("quarantine_path")
    if not qpath or not _inside_quarantine_dir(qpath):
        log.warning("Restore refused (quarantine path invalid): manifest_id=%s", manifest_id)
        return 403, {"ok": False, "code": "PROTECTED", "message": RESTORE_INVALID_QPATH_MESSAGE}
    qreal = os.path.realpath(qpath)
    if not os.path.isfile(qreal):
        return 409, {"ok": False, "message": "Quarantined file is missing."}

    # e. integrity: must be byte-identical to what was quarantined; on mismatch leave it in place
    try:
        current = compute_sha256(qreal)
    except OSError:
        return 409, {"ok": False, "message": "Quarantined file is missing."}
    if current != rec.get("sha256"):
        log.warning("Restore refused (hash mismatch): manifest_id=%s process=%s", manifest_id, name)
        db.append_audit_event("quarantine_integrity", "high",
                              f"Restore blocked: {file_name} changed while in quarantine", str(manifest_id))
        return 409, {"ok": False, "message": "File changed while in quarantine."}

    # f. destination must not be protected (is_under_protected fails closed on empty/unknown)
    if quarantine_guards.is_under_protected(original):
        log.info("Restore refused (protected destination): manifest_id=%s process=%s", manifest_id, name)
        return 403, {"ok": False, "code": "PROTECTED", "message": RESTORE_PROTECTED_MESSAGE}
    target = os.path.realpath(original)

    # g. parent folder must still exist; folders are never created
    if not os.path.isdir(os.path.dirname(target)):
        return 409, {"ok": False, "message": "Original folder no longer exists."}

    # h. never overwrite
    if os.path.lexists(target):
        return 409, {"ok": False, "message": RESTORE_EXISTS_MESSAGE}

    # os.rename fails on Windows if the target exists, closing the race window that
    # shutil.move's copy fallback would leave open.
    try:
        os.rename(qreal, target)
    except FileExistsError:
        return 409, {"ok": False, "message": RESTORE_EXISTS_MESSAGE}
    except OSError:
        log.warning("Restore move failed: manifest_id=%s process=%s", manifest_id, name)
        return 500, {"ok": False, "message": "Restore failed: could not move file."}

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
        return 409, {"ok": False, "message": "Another quarantine action is in progress. Try again."}
    try:
        return _restore(manifest_id)
    except Exception:
        log.exception("Restore failed unexpectedly for manifest_id=%s", manifest_id)
        return 500, {"ok": False, "message": "Unexpected error. See server log."}
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
        return 409, {"ok": False, "message": "Another quarantine is in progress. Try again."}
    try:
        return _quarantine(conn_id)
    except Exception:
        log.exception("Quarantine failed unexpectedly for conn_id=%s", conn_id)
        return 500, {"ok": False, "message": "Unexpected error. See server log."}
    finally:
        _lock.release()


def _quarantine(conn_id):
    # 1. Server-side lookup. The client never names a PID or a path.
    rec = connections.get_internal_connection(conn_id)
    if rec is None:
        return 404, {"ok": False, "message": "Connection not found or already closed."}

    pid = rec.get("pid")
    name = rec.get("process_name")
    raw_exe = rec.get("raw_exe")  # server-side only: never returned or logged

    # 2. Protected check first, so simulated-but-protected (rundll32) still shows the lock.
    #    is_protected_target fails closed when raw_exe is None.
    if quarantine_guards.is_protected_target(raw_exe, pid, name):
        log.info("Quarantine refused (protected): conn_id=%s process=%s", conn_id, name)
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
        return 200, {
            "ok": True,
            "simulated": True,
            "message": "Simulated quarantine: no files were touched.",
            "manifest_id": manifest_id,
        }

    # 4. Real, unprotected: re-verify and fingerprint before acting.
    failure = verify_target(rec)
    if failure is not None:
        return failure
    try:
        sha256 = compute_sha256(raw_exe)
    except OSError:
        log.info("Could not read file to hash: conn_id=%s process=%s", conn_id, name)
        return 409, {"ok": False, "message": "Could not read the program file to fingerprint it."}

    # 5. Real flow: stop the process, then move the file (a running exe is locked, so this order matters).
    ok, msg = _stop_process(rec)
    if not ok:
        log.info("Stop failed: conn_id=%s process=%s", conn_id, name)
        return (409 if msg == CHANGED_MESSAGE else 500), {"ok": False, "message": msg}

    qpath, err = _move_to_quarantine(raw_exe, sha256)
    if err is not None:
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
