"""Read-only Databricks incident snapshots. Credentials never enter API responses."""
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
import logging
import math
from threading import Lock
import time

import config

log = logging.getLogger(__name__)
COLUMNS = ("latitude_src", "longitude_src", "latitude_dest", "longitude_dest", "severity", "description", "ip")
SEVERITIES = ("low", "medium", "high", "critical")
class IncidentDataError(Exception):
    pass


def incident_error_message(error):
    """Return actionable fixed messages, never raw SDK errors or credentials."""
    message = str(error).lower()
    if "scopes" in message and "not assigned" in message:
        return "Databricks rejected the OAuth scope. The incident feed requires the sql scope; check the OAuth secret permissions and restart the backend."
    if "invalid_client" in message or "invalid client" in message:
        return "Databricks rejected the OAuth client credentials. Check the client ID and secret in backend/.env and restart the backend."
    if isinstance(error, TimeoutError):
        return "The Databricks incident query timed out. Check that the SQL warehouse is running; the backend will retry."
    return "Could not load Databricks incidents. Check backend authentication, warehouse access, and the incident table schema."

def workspace_client():
    from databricks.sdk import WorkspaceClient
    from databricks.sdk.config import Config
    # This integration only calls SQL APIs. The SDK default (all-apis) is
    # rejected by OAuth secrets restricted to the sql scope.
    return WorkspaceClient(config=Config(scopes=["sql"], http_timeout_seconds=10, retry_timeout_seconds=10))

def parse_rows(columns, rows, limit):
    indices = {column: i for i, column in enumerate(columns)}
    if not all(column in indices for column in COLUMNS):
        raise IncidentDataError("The incident table is missing required columns.")
    parsed, skipped, unknown = [], 0, 0
    for row in rows[:limit]:
        try:
            values = {name: row[indices[name]] for name in COLUMNS}
            coords = [float(values[name]) for name in COLUMNS[:4]]
            if not all(math.isfinite(x) for x in coords) or any(abs(coords[i]) > (90 if i % 2 == 0 else 180) for i in range(4)):
                raise ValueError("invalid coordinates")
        except (ValueError, TypeError, IndexError):
            skipped += 1
            continue
        severity = str(values["severity"] or "").strip().lower()
        if severity not in SEVERITIES:
            severity = "unknown"
            unknown += 1
        parsed.append(dict(zip(COLUMNS[:4], coords)) | {
            "severity": severity,
            "description": str(values["description"] or "")[:4000],
            "ip": str(values["ip"] or "")[:100],
        })
    # No primary key is supplied. A content hash plus occurrence retains even
    # identical rows and keeps IDs stable when query result order changes.
    occurrences = Counter()
    for incident in parsed:
        digest = hashlib.sha256(json.dumps(incident, sort_keys=True, ensure_ascii=False).encode()).hexdigest()[:24]
        occurrences[digest] += 1
        incident["id"] = "incident-" + digest + "-" + str(occurrences[digest])
    counts = Counter(item["severity"] for item in parsed)
    warnings = []
    if skipped:
        warnings.append(f"Skipped {skipped} rows with missing or invalid coordinates.")
    if unknown:
        warnings.append(f"{unknown} incidents have an unrecognized severity; shown as unknown.")
    return {"incidents": parsed, "counts": dict(counts), "invalid_rows": skipped, "warnings": warnings}

def fetch_incidents(client, *, limit=2000, timeout=45, clock=time.monotonic, sleep=time.sleep):
    from databricks.sdk.service.sql import Disposition, Format, StatementState
    api = client.statement_execution
    deadline = clock() + timeout
    response = api.execute_statement(
        warehouse_id=config.DATABRICKS_WAREHOUSE_ID,
        catalog="workspace", schema="default",
        statement="SELECT " + ", ".join(COLUMNS) + " FROM geospatial_incidents LIMIT " + str(limit + 1),
        format=Format.JSON_ARRAY, disposition=Disposition.INLINE,
        wait_timeout="0s", row_limit=limit + 1, byte_limit=4 * 1024 * 1024,
    )
    statement_id = response.statement_id
    try:
        while response.status and response.status.state in (StatementState.PENDING, StatementState.RUNNING):
            if clock() >= deadline:
                raise TimeoutError("Incident query timed out.")
            sleep(0.5)
            response = api.get_statement(statement_id)
        if not response.status or response.status.state != StatementState.SUCCEEDED:
            raise IncidentDataError("The Databricks statement did not succeed.")
        manifest = response.manifest
        if not manifest or not manifest.schema or manifest.schema.columns is None:
            raise IncidentDataError("The result schema was not returned.")
        columns = [c.name for c in sorted(manifest.schema.columns, key=lambda c: c.position)]
        rows = []
        chunk = response.result
        seen = set()
        while chunk is not None:
            rows.extend(chunk.data_array or [])
            index = chunk.next_chunk_index
            if index is None or len(rows) > limit:
                break
            if clock() >= deadline:
                raise TimeoutError("Incident result retrieval timed out.")
            if index in seen:
                raise IncidentDataError("Repeated incident result chunk.")
            seen.add(index)
            chunk = api.get_statement_result_chunk_n(statement_id, index)
            if chunk is None:
                raise IncidentDataError("Incident result chunk was not returned.")
        if response.result is None and manifest.total_row_count:
            raise IncidentDataError("Incident result data was not returned.")
        if manifest.total_row_count is not None and len(rows) < min(manifest.total_row_count, limit + 1):
            raise IncidentDataError("Incident result data was incomplete.")
        snapshot = parse_rows(columns, rows, limit)
        snapshot["truncated"] = bool(manifest.truncated or len(rows) > limit)
        if snapshot["truncated"]:
            snapshot["warnings"].append(f"Showing at most {limit} incident rows; the table or result exceeds this limit.")
        snapshot["fetched_at"] = datetime.now(timezone.utc).isoformat()
        snapshot["warehouse_id"] = config.DATABRICKS_WAREHOUSE_ID
        snapshot["table"] = "workspace.default.geospatial_incidents"
        return snapshot
    except Exception:
        if statement_id:
            try:
                api.cancel_execution(statement_id)
            except Exception:
                pass
        raise

class IncidentFeed:
    def __init__(self, client_factory=workspace_client, *, clock=time.monotonic, executor=None):
        self._client_factory = client_factory
        self._clock = clock
        self._pool = executor or ThreadPoolExecutor(max_workers=1, thread_name_prefix="incidents")
        self._lock = Lock()
        self._client = None
        self._snapshot = None
        self._running = False
        self._last_attempt = None
        self._error = None

    def snapshot(self):
        with self._lock:
            now = self._clock()
            if not self._running and (self._last_attempt is None or now - self._last_attempt >= config.DATABRICKS_REFRESH_SECONDS):
                self._running = True
                self._last_attempt = now
                self._pool.submit(self._refresh)
            state = "refreshing" if self._running and self._snapshot is not None else "loading" if self._running else "error" if self._error else "ready"
            result = dict(self._snapshot or {"incidents": [], "counts": {}, "warnings": [], "truncated": False, "fetched_at": None})
            result.update({"state": state, "source": "databricks", "stale": self._error is not None, "message": self._error})
            return result

    def _refresh(self):
        try:
            if self._client is None:
                self._client = self._client_factory()
            snapshot = fetch_incidents(self._client, limit=config.DATABRICKS_MAX_ROWS, timeout=config.DATABRICKS_QUERY_TIMEOUT)
            with self._lock:
                self._snapshot = snapshot
                self._error = None
        except Exception as error:
            # SDK exceptions can contain credentials/configuration. Do not expose
            # their raw text through logs or browser responses.
            log.warning("Databricks incident refresh failed (%s)", type(error).__name__)
            with self._lock:
                self._error = incident_error_message(error)
            self._client = None
        finally:
            with self._lock:
                self._running = False

    def close(self):
        self._pool.shutdown(wait=False, cancel_futures=True)

incident_feed = IncidentFeed()
