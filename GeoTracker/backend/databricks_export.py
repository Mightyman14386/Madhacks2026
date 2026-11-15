"""Opt-in export of new unsafe findings into workspace.default.geospatial_incidents.

- to_incident_row(): pure mapping from one finding to the table's 7 columns. Path-free; never
  includes raw_exe, exe paths, cmdline, local IPs, or ancestry paths.
- insert_incidents(): one parameterized multi-row INSERT (named parameters, no string-formatted values).
- A single background worker reconciles like a sync job: every pass scans ALL local findings and the
  INSERT ... WHERE NOT EXISTS lets the warehouse add only rows whose IP + coordinates it doesn't have.
  Rows deleted/truncated in Databricks are re-added on the next pass; existing rows are never duplicated.
  Passes run every DATABRICKS_EXPORT_SECONDS and immediately when a new finding appears.
  /api/connections never waits on the warehouse.
"""
import logging
import math
import threading
import time

import config
import db
import geo
import incidents
import scenarios

log = logging.getLogger("geotracker.databricks_export")

TABLE_COLUMNS = incidents.COLUMNS  # latitude_src, longitude_src, latitude_dest, longitude_dest, severity, description, ip
BATCH_SIZE = 50
FLUSH_SECONDS = float(getattr(config, "DATABRICKS_EXPORT_SECONDS", 30.0))  # full reconcile interval
DESCRIPTION_MAX = 4000

_lock = threading.Lock()
_state = {"exported": 0, "skipped": 0, "duplicates_skipped": 0, "last_error": None, "last_export_at": None}
_client = None
_stop = threading.Event()
# Every located connection the device globe has drawn this session, keyed like the table dedupe.
# Reconciled on each pass, so the incidents globe mirrors device traffic (safe and unsafe).
OBSERVED_MAX = 20000
_observed = {}
_wake = threading.Event()
_thread = None


# ---------------------------------------------------------------- mapping (pure)

def _finite(value):
    try:
        v = float(value)
    except (TypeError, ValueError):
        return None
    return v if math.isfinite(v) else None


def device_tag():
    """Suffix identifying the exporting device; part of the table-side dedupe."""
    return f" @{config.DEVICE_NAME}"


def to_incident_row(conn, origin):
    """Map one located connection (safe or unsafe) to a geospatial_incidents row, or None to skip.
    Source = device origin, destination = the connection's GeoIP point: exactly what the device globe draws."""
    coords = [_finite(origin.get("lat")), _finite(origin.get("lng")), _finite(conn.get("lat")), _finite(conn.get("lng"))]
    if any(c is None for c in coords):
        return None  # anycast / unlocated: nothing to draw
    place = ", ".join(p for p in (conn.get("city"), conn.get("country_code")) if p) or "unknown location"
    reasons = "; ".join(str(r) for r in (conn.get("reasons") or []))
    description = f"{conn.get('process_name') or 'unknown'} -> {conn.get('remote_ip')}:{conn.get('remote_port')} ({place})"
    if reasons:
        description += f": {reasons}"
    if conn.get("is_simulated"):
        description += " [simulated]"
    tag = device_tag()
    description = description[:DESCRIPTION_MAX - len(tag)] + tag
    return {
        "latitude_src": coords[0], "longitude_src": coords[1],
        "latitude_dest": coords[2], "longitude_dest": coords[3],
        "severity": str(conn.get("severity") or "unknown").lower(),
        "description": description,
        "ip": str(conn.get("remote_ip") or "")[:100],
    }


# ---------------------------------------------------------------- sender

COORD_COLUMNS = ("latitude_src", "longitude_src", "latitude_dest", "longitude_dest")
COORD_DECIMALS = 4  # ~11 m: coordinates equal at this precision count as the same point


def dedupe_key(row):
    """Redundancy key: IP + all four coordinates (rounded). Rows are per device (see device_tag)."""
    return (str(row.get("ip") or ""),) + tuple(round(float(row[c]), COORD_DECIMALS) for c in COORD_COLUMNS)


def dedupe_rows(rows):
    """Keep the first row per (ip, coordinates). Returns (unique_rows, duplicates_dropped)."""
    seen, unique = set(), []
    for row in rows:
        key = dedupe_key(row)
        if key not in seen:
            seen.add(key)
            unique.append(row)
    return unique, len(rows) - len(unique)


def _build_statement(rows):
    """Return (sql, [(name, value, type)]). Values only ever travel as named parameters.
    The table-side NOT EXISTS skips rows whose IP + coordinates are already in geospatial_incidents."""
    tuples, params = [], []
    for i, row in enumerate(rows):
        names = []
        for col in TABLE_COLUMNS:
            name = f"{col}_{i}"
            names.append(":" + name)
            is_coord = col.startswith(("latitude", "longitude"))
            params.append((name, str(row[col]), "DOUBLE" if is_coord else "STRING"))
        tuples.append("(" + ", ".join(names) + ")")
    params.append(("device_tag", device_tag(), "STRING"))
    cols = ", ".join(TABLE_COLUMNS)
    same_point = " AND ".join(
        f"round(g.{c}, {COORD_DECIMALS}) = round(v.{c}, {COORD_DECIMALS})" for c in COORD_COLUMNS)
    sql = (f"INSERT INTO geospatial_incidents ({cols}) "
           f"SELECT {cols} FROM VALUES {', '.join(tuples)} AS v({cols}) "
           f"WHERE NOT EXISTS (SELECT 1 FROM geospatial_incidents g WHERE g.ip = v.ip AND {same_point} "
           f"AND endswith(g.description, :device_tag))")
    return sql, params


def _inserted_count(resp):
    """num_inserted_rows from a DML result, or None if the response doesn't include it."""
    try:
        cols = [c.name for c in resp.manifest.schema.columns]
        return int(resp.result.data_array[0][cols.index("num_inserted_rows")])
    except Exception:
        return None


def insert_incidents(rows, wait_timeout="30s"):
    """Insert rows the table doesn't already have, with one parameterized statement.
    Returns the number actually inserted (num_inserted_rows; len(rows) if not reported),
    or None on failure. Never raises."""
    global _client
    rows = list(rows or [])
    if not rows:
        return 0
    try:
        from databricks.sdk.service.sql import StatementParameterListItem
        sql, params = _build_statement(rows)
        if _client is None:
            _client = incidents.workspace_client()
        resp = _client.statement_execution.execute_statement(
            warehouse_id=config.DATABRICKS_WAREHOUSE_ID, catalog="workspace", schema="default",
            statement=sql, wait_timeout=wait_timeout,
            parameters=[StatementParameterListItem(name=n, value=v, type=t) for n, v, t in params],
        )
        state = getattr(getattr(resp, "status", None), "state", None)
        if getattr(state, "value", state) != "SUCCEEDED":
            raise RuntimeError("statement did not succeed")
        inserted = _inserted_count(resp)
        if inserted is None:
            inserted = len(rows)
        if inserted < len(rows):
            with _lock:
                _state["duplicates_skipped"] += len(rows) - inserted  # already in the table
        return inserted
    except Exception as e:
        # SDK errors can contain credentials/configuration: log the type only, store a fixed message.
        log.warning("Databricks export failed (%s)", type(e).__name__)
        with _lock:
            _state["last_error"] = incidents.incident_error_message(e).replace("load Databricks incidents",
                                                                              "export to Databricks")
        _client = None
        return None


# ---------------------------------------------------------------- database-driven worker

def _finding_from_db(r):
    """threat_findings row -> finding dict with coordinates for to_incident_row (re-located by IP)."""
    ip = r.get("remote_ip")
    g = (scenarios.planted_geo(ip) if r.get("is_simulated") else geo.geolocate(ip)) or {}
    return {**r, "lat": g.get("lat"), "lng": g.get("lng"), "status": "unsafe",
            "is_simulated": bool(r.get("is_simulated"))}


def observe_connections(connections, origin):
    """Record the located connections from a device snapshot for export. Wakes the worker when a new
    route appears. Unsafe rows should come first so they win over a safe row for the same route."""
    if not config.DATABRICKS_EXPORT_ENABLED:
        return 0
    added = 0
    with _lock:
        for conn in connections or []:
            if conn.get("is_simulated") and not config.DATABRICKS_EXPORT_SIMULATED:
                continue
            row = to_incident_row(conn, origin)
            if row is None:
                continue
            key = dedupe_key(row)
            if key in _observed:
                continue
            if len(_observed) >= OBSERVED_MAX:
                _observed.pop(next(iter(_observed)))  # oldest out
            _observed[key] = row
            added += 1
    if added:
        _wake.set()
    return added


def forget_process(process_name):
    """Stop re-sending a program's routes (e.g. after it was permanently deleted). Returns rows dropped.
    Rows already in the Databricks table are left as they are."""
    if not process_name:
        return 0
    prefix = f"{process_name} -> "
    with _lock:
        keys = [k for k, row in _observed.items() if row["description"].startswith(prefix)]
        for k in keys:
            del _observed[k]
    return len(keys)


def _flush_observed(wait_timeout):
    """Send every observed connection; the table-side NOT EXISTS skips ones already present.
    Returns rows inserted, or None if a batch failed."""
    with _lock:
        rows = list(_observed.values())
    inserted_total = 0
    for i in range(0, len(rows), BATCH_SIZE):
        inserted = insert_incidents(rows[i:i + BATCH_SIZE], wait_timeout=wait_timeout)
        if inserted is None:
            return None
        inserted_total += inserted
        with _lock:
            _state["exported"] += inserted
            _state["last_error"] = None
            _state["last_export_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return inserted_total


def enqueue(finding):
    """Called on first sight of a finding: wake the worker. The row itself is read from SQLite."""
    if config.DATABRICKS_EXPORT_ENABLED:
        _wake.set()
        return True
    return False


def flush_once(wait_timeout="30s"):
    """One reconcile pass over ALL local findings, BATCH_SIZE at a time. The warehouse inserts only
    rows whose IP + coordinates it doesn't already have. Returns rows actually inserted. Never raises.
    exported_at records when a finding was last confirmed present ('skipped:<ts>' if unlocatable).
    On a failed batch the pass stops and the next pass retries from the start."""
    inserted_total, offset = 0, 0
    origin = geo.get_origin()
    while not _stop.is_set():
        try:
            rows = db.get_unexported_findings(BATCH_SIZE, config.DATABRICKS_EXPORT_SIMULATED,
                                              only_unexported=False, offset=offset)
        except Exception:
            break  # DB not ready
        if not rows:
            break
        offset += len(rows)
        mapped, ids, skipped = [], [], []
        for r in rows:
            row = to_incident_row(_finding_from_db(r), origin)
            (skipped if row is None else ids).append(r["conn_id"])
            if row is not None:
                mapped.append(row)
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        if skipped:
            db.mark_findings_exported(skipped, stamp=f"skipped:{now}")
            with _lock:
                _state["skipped"] += len(skipped)
        if not mapped:
            continue
        mapped, dropped = dedupe_rows(mapped)  # same IP + coordinates in this batch: send once
        if dropped:
            with _lock:
                _state["duplicates_skipped"] += dropped
        inserted = insert_incidents(mapped, wait_timeout=wait_timeout)
        if inserted is None:
            break  # failure: nothing stamped; next pass retries
        db.mark_findings_exported(ids)
        inserted_total += inserted
        with _lock:
            _state["exported"] += inserted
            _state["last_error"] = None
            _state["last_export_at"] = now
    observed = _flush_observed(wait_timeout)
    return inserted_total + (observed or 0)


def _run():
    while not _stop.is_set():
        try:
            flush_once()
        except Exception:
            log.exception("Databricks export pass failed")
        _wake.wait(FLUSH_SECONDS)
        _wake.clear()


def start():
    global _thread
    if not config.DATABRICKS_EXPORT_ENABLED or (_thread is not None and _thread.is_alive()):
        return
    _stop.clear()
    _thread = threading.Thread(target=_run, name="databricks-export", daemon=True)
    _thread.start()
    log.info("Databricks export enabled (simulated=%s)", config.DATABRICKS_EXPORT_SIMULATED)


def stop():
    """Stop the worker and make one last short flush attempt. Never raises."""
    try:
        _stop.set()
        _wake.set()
        if _thread is not None:
            _thread.join(timeout=FLUSH_SECONDS + 1)
        if config.DATABRICKS_EXPORT_ENABLED:
            flush_once(wait_timeout="10s")
    except Exception:
        log.exception("Databricks export stop failed")


def export_state():
    try:
        pending = db.count_unexported_findings(config.DATABRICKS_EXPORT_SIMULATED)
    except Exception:
        pending = None  # DB not ready
    with _lock:
        return {"enabled": config.DATABRICKS_EXPORT_ENABLED, "simulated": config.DATABRICKS_EXPORT_SIMULATED,
                "exported": _state["exported"], "skipped": _state["skipped"],
                "duplicates_skipped": _state["duplicates_skipped"], "pending": pending,
                "last_export_at": _state["last_export_at"], "last_error": _state["last_error"]}
