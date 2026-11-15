"""SQLite audit layer. Parameterized queries only; one lock guards the shared connection.

PRIVACY: nothing written here may contain raw_exe, cmdline, or any unredacted path,
with ONE deliberate exception: quarantine_manifest.original_path_private (see below).
"""
import json
import logging
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone

import config

log = logging.getLogger("geotrench.db")

FINDING_UPDATE_THROTTLE_SECONDS = 30.0

_lock = threading.RLock()
_conn = None
_db_path = None
_last_write = {}        # conn_id -> monotonic time of last DB write (throttle)
_geofence_version = 0   # bumped on every geofence append; readers use it to invalidate caches

_SCHEMA = """
CREATE TABLE IF NOT EXISTS threat_findings (
    id INTEGER PRIMARY KEY,
    conn_id TEXT UNIQUE,
    pid INT,
    process_name TEXT,
    remote_ip TEXT,
    remote_port INT,
    country_code TEXT,
    city TEXT,
    asn_org TEXT,
    ancestry_json TEXT,
    rules_json TEXT,
    reasons_json TEXT,
    severity TEXT,
    first_seen TEXT,
    last_seen TEXT,
    is_simulated INT
);
CREATE INDEX IF NOT EXISTS idx_findings_first_seen ON threat_findings(first_seen);
CREATE INDEX IF NOT EXISTS idx_findings_last_seen ON threat_findings(last_seen);
CREATE INDEX IF NOT EXISTS idx_findings_country ON threat_findings(country_code);

CREATE TABLE IF NOT EXISTS geofence_log (
    id INTEGER PRIMARY KEY,
    ts TEXT,
    action TEXT CHECK(action IN ('block','unblock')),
    country_code TEXT,
    ips_json TEXT,
    rule_name TEXT,
    enforced INT,
    command TEXT,
    note TEXT
);
CREATE INDEX IF NOT EXISTS idx_geofence_ts ON geofence_log(ts);
CREATE INDEX IF NOT EXISTS idx_geofence_country ON geofence_log(country_code);

-- original_path_redacted is for display. original_path_private holds the REAL path,
-- because restoring a quarantined file needs to know exactly where it came from.
-- original_path_private is server-side only: it must NEVER be returned by any API,
-- shown in the UI, or sent to an LLM.
CREATE TABLE IF NOT EXISTS quarantine_manifest (
    id INTEGER PRIMARY KEY,
    ts TEXT,
    pid INT,
    process_name TEXT,
    original_path_redacted TEXT,
    original_path_private TEXT,
    quarantine_path TEXT,
    sha256 TEXT,
    status TEXT CHECK(status IN ('quarantined','restored','dry_run')),
    is_simulated INT,
    note TEXT
);
CREATE INDEX IF NOT EXISTS idx_quarantine_ts ON quarantine_manifest(ts);

CREATE TABLE IF NOT EXISTS agent_actions (
    id INTEGER PRIMARY KEY,
    ts TEXT,
    conn_id TEXT,
    proposed_action TEXT CHECK(proposed_action IN ('quarantine','geofence','monitor')),
    rationale TEXT,
    status TEXT CHECK(status IN ('proposed','approved','rejected','executed')),
    decided_ts TEXT
);
CREATE INDEX IF NOT EXISTS idx_agent_ts ON agent_actions(ts);
CREATE INDEX IF NOT EXISTS idx_agent_decided_ts ON agent_actions(decided_ts);

-- Append-only audit events for actions that don't map 1:1 to a row (restore, integrity failures).
-- Messages are short plain-English strings and never contain paths. Rows are never deleted.
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY,
    ts TEXT,
    type TEXT,
    severity TEXT,
    message TEXT,
    ref_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
"""


def _migrate(c):
    """Safe additive migrations for databases created by earlier steps."""
    cols = {r["name"] for r in c.execute("PRAGMA table_info(quarantine_manifest)")}
    if "restored_at" not in cols:
        c.execute("ALTER TABLE quarantine_manifest ADD COLUMN restored_at TEXT")

    # Databricks export bookkeeping: NULL = not yet sent.
    tf_cols = {r["name"] for r in c.execute("PRAGMA table_info(threat_findings)")}
    if "exported_at" not in tf_cols:
        c.execute("ALTER TABLE threat_findings ADD COLUMN exported_at TEXT")

    # Step 8B geofence fields. Fixed statements only (no interpolation).
    geo_cols = {r["name"] for r in c.execute("PRAGMA table_info(geofence_log)")}
    for name, stmt in (
        ("ip_count", "ALTER TABLE geofence_log ADD COLUMN ip_count INT"),
        ("mode", "ALTER TABLE geofence_log ADD COLUMN mode TEXT"),
        ("expires_at", "ALTER TABLE geofence_log ADD COLUMN expires_at TEXT"),
        ("source", "ALTER TABLE geofence_log ADD COLUMN source TEXT"),
        ("scope", "ALTER TABLE geofence_log ADD COLUMN scope TEXT"),
        ("range_count", "ALTER TABLE geofence_log ADD COLUMN range_count INT"),
    ):
        if name not in geo_cols:
            c.execute(stmt)


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _db():
    if _conn is None:
        raise RuntimeError("database not initialized")
    return _conn


def _rows(cur):
    return [dict(r) for r in cur.fetchall()]


# ---------------------------------------------------------------- lifecycle

def init_db(path=None):
    """Open (creating if needed) the database. path defaults to config.DB_PATH."""
    global _conn, _db_path, _geofence_version
    with _lock:
        close()
        _db_path = str(path or config.DB_PATH)
        _conn = sqlite3.connect(_db_path, check_same_thread=False)
        _conn.row_factory = sqlite3.Row
        _conn.execute("PRAGMA journal_mode=WAL")
        _conn.execute("PRAGMA foreign_keys=ON")
        _conn.executescript(_SCHEMA)
        _migrate(_conn)
        _conn.commit()
        _last_write.clear()
        _geofence_version += 1
    return _db_path


def close():
    global _conn
    with _lock:
        if _conn is not None:
            try:
                _conn.close()
            except Exception:
                pass
        _conn = None


def db_path():
    return _db_path


_COUNT_QUERIES = {
    "threat_findings": "SELECT COUNT(*) FROM threat_findings",
    "geofence_log": "SELECT COUNT(*) FROM geofence_log",
    "quarantine_manifest": "SELECT COUNT(*) FROM quarantine_manifest",
    "agent_actions": "SELECT COUNT(*) FROM agent_actions",
    "audit_log": "SELECT COUNT(*) FROM audit_log",
}


def row_counts():
    with _lock:
        c = _db()
        return {t: c.execute(q).fetchone()[0] for t, q in _COUNT_QUERIES.items()}


# ---------------------------------------------------------------- findings

def upsert_finding(conn):
    """Record an unsafe connection. Returns True only on first sight of its conn_id.

    Reads only redacted fields. raw_exe / exe / cmdline are deliberately never read.
    """
    cid = conn.get("id") or conn.get("conn_id")
    if not cid:
        return False
    now_m = time.monotonic()
    with _lock:
        last = _last_write.get(cid)
        if last is not None and now_m - last < FINDING_UPDATE_THROTTLE_SECONDS:
            return False
        c = _db()
        now = _now()
        cur = c.execute(
            "INSERT OR IGNORE INTO threat_findings (conn_id, pid, process_name, remote_ip, remote_port, "
            "country_code, city, asn_org, ancestry_json, rules_json, reasons_json, severity, "
            "first_seen, last_seen, is_simulated) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                cid,
                conn.get("pid"),
                conn.get("process_name"),
                conn.get("remote_ip"),
                conn.get("remote_port"),
                conn.get("country_code"),
                conn.get("city"),
                conn.get("asn_org"),
                json.dumps([str(n) for n in (conn.get("ancestry") or [])]),
                json.dumps(list(conn.get("rules_fired") or [])),
                json.dumps(list(conn.get("reasons") or [])),
                conn.get("severity"),
                conn.get("first_seen") or now,
                now,
                1 if conn.get("is_simulated") else 0,
            ),
        )
        is_new = cur.rowcount == 1
        if not is_new:
            c.execute("UPDATE threat_findings SET last_seen = ? WHERE conn_id = ?", (now, cid))
        c.commit()
        _last_write[cid] = now_m
        return is_new


def get_recent_findings_for(process_name=None, remote_ip=None):
    """Summary of past findings matching a process name and/or remote IP (both optional)."""
    where, params = [], []
    if process_name:
        where.append("process_name = ? COLLATE NOCASE")
        params.append(process_name)
    if remote_ip:
        where.append("remote_ip = ?")
        params.append(remote_ip)
    clause = (" WHERE " + " AND ".join(where)) if where else ""  # fixed fragments only; values are bound
    with _lock:
        c = _db()
        row = c.execute(
            "SELECT COUNT(*) AS n, MIN(first_seen) AS first_seen, MAX(last_seen) AS last_seen, "
            "SUM(is_simulated) AS simulated FROM threat_findings" + clause, params,
        ).fetchone()
        by_sev = {
            r["severity"]: r["n"]
            for r in c.execute(
                "SELECT severity, COUNT(*) AS n FROM threat_findings" + clause + " GROUP BY severity", params,
            )
        }
    return {
        "process_name": process_name,
        "remote_ip": remote_ip,
        "count": row["n"],
        "simulated_count": row["simulated"] or 0,
        "by_severity": by_sev,
        "first_seen": row["first_seen"],
        "last_seen": row["last_seen"],
    }


def get_unexported_findings(limit, include_simulated, only_unexported=True, offset=0):
    """Oldest-first findings for the Databricks export. only_unexported=False pages through ALL findings
    (the reconcile scan); the warehouse then inserts only rows it doesn't already have."""
    sql = ("SELECT * FROM threat_findings WHERE 1 = 1"
           + (" AND exported_at IS NULL" if only_unexported else "")
           + ("" if include_simulated else " AND is_simulated = 0")
           + " ORDER BY id LIMIT ? OFFSET ?")  # fixed fragments only; values are bound
    with _lock:
        rows = _rows(_db().execute(sql, (int(limit), int(offset))))
    for r in rows:
        for key in ("ancestry_json", "rules_json", "reasons_json"):
            try:
                r[key[:-5]] = json.loads(r.pop(key) or "[]")
            except ValueError:
                r[key[:-5]] = []
    return rows


def count_unexported_findings(include_simulated):
    sql = ("SELECT COUNT(*) FROM threat_findings WHERE exported_at IS NULL"
           + ("" if include_simulated else " AND is_simulated = 0"))
    with _lock:
        return _db().execute(sql).fetchone()[0]


def mark_findings_exported(conn_ids, stamp=None):
    """Stamp findings as sent (stamp may be e.g. 'skipped:<ts>' for rows that can't be exported)."""
    ids = [str(i) for i in conn_ids or []]
    if not ids:
        return 0
    with _lock:
        c = _db()
        cur = c.executemany("UPDATE threat_findings SET exported_at = ? WHERE conn_id = ?",
                            [(stamp or _now(), i) for i in ids])
        c.commit()
        return cur.rowcount


# ---------------------------------------------------------------- geofence

def geofence_version():
    return _geofence_version


def append_geofence_event(action, country_code, ips, rule_name, enforced, command, note,
                          ip_count=None, mode=None, expires_at=None, source=None,
                          scope=None, range_count=None):
    """Append one geofence event and bump geofence_version (invalidates readers' caches).
    ips must be public remote IPs only (never local, gateway, or DNS addresses)."""
    global _geofence_version
    if action not in ("block", "unblock"):
        raise ValueError(f"invalid geofence action: {action!r}")
    ips = list(ips or [])
    with _lock:
        c = _db()
        cur = c.execute(
            "INSERT INTO geofence_log (ts, action, country_code, ips_json, rule_name, enforced, command, note, "
            "ip_count, mode, expires_at, source, scope, range_count) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (_now(), action, str(country_code).strip().upper(), json.dumps(ips),
             rule_name, 1 if enforced else 0, command, note,
             len(ips) if ip_count is None else ip_count, mode, expires_at, source, scope, range_count),
        )
        c.commit()
        _geofence_version += 1
        return cur.lastrowid


def get_active_geofences():
    """The block row behind each currently active region, oldest first (replayed from geofence_log)."""
    with _lock:
        c = _db()
        active = _replay(c.execute("SELECT id, action, country_code FROM geofence_log ORDER BY id").fetchall())
        if not active:
            return []
        rows = []
        for row_id in sorted(active.values()):
            r = c.execute("SELECT * FROM geofence_log WHERE id = ?", (row_id,)).fetchone()
            if r is not None:
                rows.append(dict(r))
    return rows


def _replay(rows):
    active = {}
    for r in rows:
        if r["action"] == "block":
            active[r["country_code"]] = r["id"]
        else:
            active.pop(r["country_code"], None)
    return active  # country_code -> id of the block row that made it active


def get_blocked_regions():
    """Current blocked set, derived by replaying geofence_log in order. Rows are never deleted to undo."""
    with _lock:
        rows = _db().execute("SELECT id, action, country_code FROM geofence_log ORDER BY id").fetchall()
    return sorted(_replay(rows))


def get_geofence_history(limit=50):
    with _lock:
        return _rows(_db().execute("SELECT * FROM geofence_log ORDER BY id DESC LIMIT ?", (int(limit),)))


# ---------------------------------------------------------------- quarantine

def list_quarantine_records(limit=200):
    """Newest first. Omits original_path_private AND quarantine_path (folder layout is not UI business)."""
    limit = max(1, min(int(limit), 500))
    with _lock:
        rows = _rows(_db().execute(
            "SELECT id, ts, pid, process_name, original_path_redacted, sha256, status, "
            "restored_at, is_simulated, note FROM quarantine_manifest ORDER BY id DESC LIMIT ?", (limit,)))
    for r in rows:
        r["sha256_short"] = (r.pop("sha256") or "")[:8]
    return rows

def add_quarantine_record(pid, process_name, original_path_redacted, original_path_private,
                          quarantine_path, sha256, status, is_simulated, note=None):
    with _lock:
        c = _db()
        cur = c.execute(
            "INSERT INTO quarantine_manifest (ts, pid, process_name, original_path_redacted, "
            "original_path_private, quarantine_path, sha256, status, is_simulated, note) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (_now(), pid, process_name, original_path_redacted, original_path_private,
             quarantine_path, sha256, status, 1 if is_simulated else 0, note),
        )
        c.commit()
        return cur.lastrowid


def update_quarantine_status(record_id, status):
    with _lock:
        c = _db()
        cur = c.execute("UPDATE quarantine_manifest SET status = ? WHERE id = ?", (status, record_id))
        c.commit()
        return cur.rowcount == 1


def mark_quarantine_restored(record_id, file_name):
    """Set status='restored' + restored_at and append a 'Restored <file_name>' audit event, atomically.
    Only transitions from 'quarantined'. file_name must be a bare name, never a path."""
    with _lock:
        c = _db()
        now = _now()
        cur = c.execute(
            "UPDATE quarantine_manifest SET status = 'restored', restored_at = ? "
            "WHERE id = ? AND status = 'quarantined'", (now, record_id))
        if cur.rowcount != 1:
            c.rollback()
            return False
        c.execute("INSERT INTO audit_log (ts, type, severity, message, ref_id) VALUES (?,?,?,?,?)",
                  (now, "quarantine_restore", "info", f"Restored {file_name}", str(record_id)))
        c.commit()
        return True


def append_audit_event(event_type, severity, message, ref_id=None):
    """Append one audit event. message must be plain English with no paths."""
    with _lock:
        c = _db()
        cur = c.execute("INSERT INTO audit_log (ts, type, severity, message, ref_id) VALUES (?,?,?,?,?)",
                        (_now(), event_type, severity, message, None if ref_id is None else str(ref_id)))
        c.commit()
        return cur.lastrowid


def get_quarantine_record(record_id, include_private=False):
    """include_private=True is for server-side restore only. Never pass it on an API path."""
    with _lock:
        row = _db().execute("SELECT * FROM quarantine_manifest WHERE id = ?", (record_id,)).fetchone()
    if row is None:
        return None
    rec = dict(row)
    if not include_private:
        rec.pop("original_path_private", None)
    return rec


# ---------------------------------------------------------------- agent

def add_agent_action(conn_id, proposed_action, rationale, status="proposed"):
    with _lock:
        c = _db()
        cur = c.execute(
            "INSERT INTO agent_actions (ts, conn_id, proposed_action, rationale, status) VALUES (?,?,?,?,?)",
            (_now(), conn_id, proposed_action, rationale, status),
        )
        c.commit()
        return cur.lastrowid


def update_agent_action(action_id, status):
    with _lock:
        c = _db()
        cur = c.execute("UPDATE agent_actions SET status = ?, decided_ts = ? WHERE id = ?",
                        (status, _now(), action_id))
        c.commit()
        return cur.rowcount == 1


def get_agent_action(action_id):
    with _lock:
        row = _db().execute("SELECT * FROM agent_actions WHERE id = ?", (action_id,)).fetchone()
    return dict(row) if row is not None else None


# ---------------------------------------------------------------- retention

def purge_older_than(days=None):
    """Delete rows older than `days` (default config.RETENTION_DAYS). Returns {table: rows_removed}.

    Geofence: the block row behind each still-active region is kept, so the derived
    blocked set is identical before and after. Quarantine: only 'restored'/'dry_run'
    rows are purged; 'quarantined' rows are kept because their files still need restoring.
    """
    days = config.RETENTION_DAYS if days is None else days
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="seconds")
    removed = {}
    with _lock:
        c = _db()
        try:
            removed["threat_findings"] = c.execute(
                "DELETE FROM threat_findings WHERE last_seen < ?", (cutoff,)).rowcount
            removed["quarantine_manifest"] = c.execute(
                "DELETE FROM quarantine_manifest WHERE ts < ? AND status IN ('restored','dry_run')",
                (cutoff,)).rowcount
            removed["agent_actions"] = c.execute(
                "DELETE FROM agent_actions WHERE ts < ?", (cutoff,)).rowcount

            rows = c.execute("SELECT id, ts, action, country_code FROM geofence_log ORDER BY id").fetchall()
            before = _replay(rows)
            keep = set(before.values())
            doomed = [(r["id"],) for r in rows if r["ts"] < cutoff and r["id"] not in keep]
            c.executemany("DELETE FROM geofence_log WHERE id = ?", doomed)
            removed["geofence_log"] = len(doomed)

            after = _replay(c.execute("SELECT id, action, country_code FROM geofence_log ORDER BY id").fetchall())
            if set(after) != set(before):
                raise RuntimeError("purge would change blocked regions")
            c.commit()
        except Exception:
            c.rollback()
            raise
    for cid in list(_last_write):  # throttle entries may point at purged rows
        _last_write.pop(cid, None)
    return removed


# ---------------------------------------------------------------- audit feed

def _place(city, country):
    return city or country or "unknown location"


def get_audit_events(limit=50):
    """Newest-first ticker events across all tables. Messages never contain paths."""
    limit = max(1, min(int(limit), 500))
    events = []
    with _lock:
        c = _db()
        for r in c.execute("SELECT * FROM threat_findings ORDER BY first_seen DESC LIMIT ?", (limit,)):
            demo = " (demo)" if r["is_simulated"] else ""
            events.append({
                "ts": r["first_seen"], "type": "threat_detected", "severity": r["severity"],
                "message": f"{(r['severity'] or 'unknown').capitalize()} threat: {r['process_name']} "
                           f"to {r['remote_ip']}:{r['remote_port']} in "
                           f"{_place(r['city'], r['country_code'])}{demo}",
                "ref_id": r["conn_id"],
            })
        for r in c.execute("SELECT * FROM geofence_log ORDER BY id DESC LIMIT ?", (limit,)):
            if r["source"] is not None:
                continue  # user/ttl/startup_sweep/shutdown rows: geofence.py writes a richer audit_log event
            mode = "" if r["enforced"] else " (dry-run)"
            verb = "Blocked traffic to" if r["action"] == "block" else "Unblocked"
            events.append({
                "ts": r["ts"], "type": f"geofence_{r['action']}", "severity": "info",
                "message": f"{verb} {r['country_code']}{mode}", "ref_id": str(r["id"]),
            })
        for r in c.execute("SELECT * FROM quarantine_manifest ORDER BY ts DESC LIMIT ?", (limit,)):
            if r["status"] == "dry_run" and not r["is_simulated"]:
                msg = f"Quarantine of {r['process_name']} incomplete: process stopped, file not moved"
            else:
                # A restored row was still quarantined at r["ts"]; the restore itself is in audit_log.
                msg = {
                    "quarantined": f"Quarantined {r['process_name']}",
                    "restored": f"Quarantined {r['process_name']}",
                    "dry_run": f"Simulated quarantine of {r['process_name']} (dry-run)",
                }.get(r["status"], f"Quarantine update for {r['process_name']}")
            events.append({"ts": r["ts"], "type": "quarantine", "severity": "info",
                           "message": msg, "ref_id": str(r["id"])})
        for r in c.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)):
            events.append({"ts": r["ts"], "type": r["type"], "severity": r["severity"],
                           "message": r["message"], "ref_id": r["ref_id"]})
        for r in c.execute("SELECT * FROM agent_actions ORDER BY ts DESC LIMIT ?", (limit,)):
            events.append({
                "ts": r["ts"], "type": "agent_proposed", "severity": "info",
                "message": f"AI agent proposed: {r['proposed_action']} for connection {r['conn_id']}",
                "ref_id": str(r["id"]),
            })
            if r["decided_ts"] and r["status"] != "proposed":
                events.append({
                    "ts": r["decided_ts"], "type": "agent_decision", "severity": "info",
                    "message": f"Agent proposal #{r['id']} ({r['proposed_action']}) {r['status']}",
                    "ref_id": str(r["id"]),
                })
    events.sort(key=lambda e: (e["ts"] or "", e["type"], e["ref_id"] or ""), reverse=True)
    return events[:limit]
