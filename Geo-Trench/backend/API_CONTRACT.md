# Geo-Trench Backend API Contract

For frontend developers. Everything you need is here; you shouldn't need to read the backend code.

---

## 1. Running the backend

From `Geo-Trench/backend` (the venv must exist; see `../TESTING.md`):

| Command | What it does |
|---|---|
| `python run.py` | Asks for Administrator (UAC prompt), then runs the server **hidden** in the background. Firewall actions are **real** if `ENFORCE_FIREWALL=true` in `backend/.env`. |
| `python run.py --no-elevate` | Runs in the current terminal **without** admin. Everything works, but firewall actions are **dry runs** and some processes show as `unknown`. Use this for UI development. |
| `python run.py --status` | Is it running, and in which mode? |
| `python run.py --stop` | Clean stop. Removes every Geo-Trench firewall rule and ends open event streams. |

- **Base URL:** `http://127.0.0.1:8000`
- **CORS:** only the origins in `CORS_ORIGINS` (backend `.env`) may call the API. Default: `http://localhost:5173,http://127.0.0.1:5173`.
- **Logs** (hidden mode): `backend/logs/server.log`.

---

## 2. Conventions

- **Send ids, never targets.** Actions take a `conn_id` (12 hex chars), `manifest_id` (positive int), or `country_code` (2 letters). Never send a PID or a file path; unknown fields are rejected with **422**.
- **Every failure** has the shape `{"ok": false, "message": "<plain English>"}`, sometimes with `"code": "PROTECTED"`. **Show `message` verbatim.**
- **Action responses** include `"op_id"`: the id of the live operation you can follow on the event stream. It is `null` when the request failed before an operation started (validation, confirmation missing, busy).
- **The backend is the source of truth.** UI locks (e.g. on protected processes) are cosmetic; always handle the server's refusal.
- **Privacy:** no response or event ever contains real file paths, the Windows username, the hostname, or local/gateway/DNS IPs. Paths you do see are already redacted (`C:\Users\<user>\...`).
- **Simulated items** (`is_simulated: true`, negative PIDs, `203.0.113.x` IPs) are demo threats. Actions on them are dry runs. Always show a **SIMULATED** label.
- **422** responses come from request validation and use FastAPI's default shape `{"detail": [...]}`, not `{ok, message}`.

---

## 3. Endpoints

Legend: 🔎 read-only · ⚙️ changes the system

### 3.1 Status

#### 🔎 `GET /api/health`
```json
{
  "status": "ok", "is_admin": true, "demo_mode": false, "enforcement_enabled": true,
  "geoip_loaded": true, "geoip_fallback": false,
  "databricks_export": { "enabled": true, "simulated": false, "exported": 5, "skipped": 0,
                         "duplicates_skipped": 10, "pending": 0,
                         "last_export_at": "2026-11-15T11:14:50Z", "last_error": null }
}
```

#### 🔎 `GET /api/capabilities`
Use this to enable or disable UI controls.
```json
{
  "is_admin": true,
  "firewall_mode": "enforced",
  "firewall_mode_reason": "ENFORCE_FIREWALL is true and running as administrator",
  "demo_mode": false,
  "geoip_fallback": false,
  "reset_connections_enabled": true,
  "ttl_minutes": 30.0,
  "features": { "quarantine": true, "restore": true, "geofence": true,
                "stop_process": false, "events_stream": true }
}
```
`firewall_mode` is `"enforced"` or `"dry_run"`. `firewall_mode_reason` is one of `"ENFORCE_FIREWALL is false"`, `"Not running as administrator"`, `"ENFORCE_FIREWALL is true and running as administrator"`.

### 3.2 Live data

#### 🔎 `GET /api/connections` (poll every 2–3 s, and on `connections_changed`)
```json
{
  "origin": { "lat": 43.0731, "lng": -89.4012, "name": "Madison, WI" },
  "connections": [{
    "id": "3f9a1c0b7e2d", "pid": 1234, "process_name": "chrome.exe",
    "exe": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    "ancestry": ["explorer.exe", "chrome.exe"],
    "ancestry_detail": [{ "pid": 4321, "name": "explorer.exe", "exe": "C:\\Windows\\explorer.exe" }],
    "local_port": 49731, "remote_ip": "142.250.80.46", "remote_port": 443,
    "country_code": "US", "country_name": "United States", "city": null, "asn_org": "Google LLC",
    "lat": 37.751, "lng": -97.822,
    "status": "safe", "severity": "low", "rules_fired": [], "reasons": [],
    "is_protected": true, "is_simulated": false, "first_seen": "2026-11-15T04:22:36+00:00"
  }],
  "anycast": [{ "id": "...", "pid": 0, "process_name": "...", "remote_ip": "1.1.1.1", "remote_port": 443,
                "provider": "Cloudflare DNS", "asn_org": "Cloudflare, Inc.",
                "status": "safe", "severity": "low", "rules_fired": [], "reasons": [] }],
  "stats": { "total": 25, "safe": 21, "unsafe": 4, "anycast": 0, "hidden_by_geofence": 0, "blocked_regions": [] },
  "geoip_fallback": false, "truncated": false, "warnings": [], "generated_ms": 34.2
}
```
- `status`: `safe` | `unsafe`. `severity`: `low` | `medium` | `high` | `critical`.
- `id` is stable across polls; use it as the React key and as `conn_id` in actions.
- Connections to geofenced countries are removed and counted in `stats.hidden_by_geofence`.
- `city` is often `null` (country-level location). Anycast endpoints have no coordinates and are in `anycast`.

#### 🔎 `GET /api/audit?limit=50` (max 500)
Newest-first list of `{ts, type, severity, message, ref_id}`. Types: `threat_detected`, `quarantine`, `quarantine_restore`, `quarantine_integrity`, `geofence_block`, `geofence_unblock`, `geofence_update`, `geofence_failed`, `geofence_orphan`, `agent_proposed`, `agent_decision`.

#### 🔎 `GET /api/incidents` (Databricks incident globe; poll every 3 s)
```json
{
  "incidents": [{ "id": "incident-<hash>-1", "latitude_src": 43.0731, "longitude_src": -89.4012,
                  "latitude_dest": 55.7558, "longitude_dest": 37.6173, "severity": "high",
                  "description": "updater.exe -> 203.0.113.10:4444 (Moscow, RU): ...", "ip": "203.0.113.10" }],
  "counts": { "high": 1 }, "warnings": [], "truncated": false,
  "fetched_at": "2026-11-15T11:07:53.553329+00:00", "warehouse_id": "...",
  "table": "workspace.default.geospatial_incidents",
  "state": "ready", "source": "databricks", "stale": false, "message": null
}
```
- `state`: `loading` | `refreshing` | `ready` | `error`. The backend queries Databricks at most every 30 s.
- **503** only while erroring **before the first successful fetch**; afterwards errors return 200 with `stale: true` and the last good data. Error `message`s are fixed strings, e.g. `"Could not load Databricks incidents. Check backend authentication, warehouse access, and the incident table schema."`.

#### 🔎 `GET /api/origin`
`{lat, lng, name}`. Also included in `/api/connections`.

### 3.3 Quarantine

#### ⚙️ `POST /api/quarantine`
Body: `{"conn_id": "3f9a1c0b7e2d"}`. Stops the connection's process and moves its program file into quarantine. For simulated items, nothing is touched.

| Status | Body |
|---|---|
| 200 | `{"ok": true, "simulated": false, "message": "Quarantined and stopped.", "manifest_id": 7, "sha256_short": "1a2b3c4d", "op_id": "quarantine-3"}` |
| 200 | `{"ok": true, "simulated": true, "message": "Simulated quarantine: no files were touched.", "manifest_id": 8, "op_id": "quarantine-4"}` |
| 403 | `{"ok": false, "code": "PROTECTED", "message": "Safety Override: Cannot delete OS file.", "op_id": "..."}` |
| 404 | `"Connection not found or already closed."` |
| 409 | `"Process changed since it was detected. Refresh and try again."` |
| 409 | `"Could not read the program file to fingerprint it."` |
| 409 | `"Another quarantine is in progress. Try again."` (`op_id: null`) |
| 500 | `"File is locked by the system. The process was stopped but the file was not moved."` (+ `manifest_id`) |
| 500 | `"Access denied inspecting the process. Run the server as Administrator."` |
| 500 | `"Access denied stopping the process. Run the server as Administrator."` |
| 500 | `"Access denied force-stopping the process."` |
| 500 | `"The process would not stop."` |
| 500 | `"Unexpected error. See server log."` |
| 422 | bad or extra fields |

#### ⚙️ `POST /api/quarantine/restore`
Body: `{"manifest_id": 7}`. Moves the file back. **Does not relaunch the program.**

| Status | Body |
|---|---|
| 200 | `{"ok": true, "message": "Restored to original location. Not relaunched.", "manifest_id": 7, "file_name": "test_agent.exe", "restored_to": "C:\\Users\\<user>\\AppData\\Local\\Temp\\test_agent.exe", "sha256_short": "1a2b3c4d", "op_id": "restore-1"}` |
| 400 | `"Simulated threat: nothing to restore."` |
| 403 | `{"code": "PROTECTED", "message": "Safety Override: Quarantine path is invalid."}` |
| 403 | `{"code": "PROTECTED", "message": "Safety Override: Cannot restore into a protected OS location."}` |
| 404 | `"Quarantine record not found."` |
| 409 | `"Not in quarantine (status: <status>)."` e.g. `(status: restored)` |
| 409 | `"Quarantined file is missing."` |
| 409 | `"File changed while in quarantine."` |
| 409 | `"Original folder no longer exists."` |
| 409 | `"A file already exists at the original location."` |
| 409 | `"Another quarantine action is in progress. Try again."` (`op_id: null`) |
| 500 | `"Restore failed: could not move file."` |
| 500 | `"Unexpected error. See server log."` |

#### ⚙️ `POST /api/quarantine/delete`
Body: `{"manifest_id": 7}`. **Permanently** deletes the quarantined file (only ever a file inside the quarantine folder). The record stays in history with status `deleted`; a deleted file can never be restored.

| Status | Body |
|---|---|
| 200 | `{"ok": true, "message": "Permanently deleted from quarantine.", "manifest_id": 7, "file_name": "test_agent.exe", "op_id": "delete_quarantine-1"}` |
| 400 | `"Simulated threat: nothing to delete."` |
| 403 | `{"code": "PROTECTED", "message": "Safety Override: Quarantine path is invalid."}` |
| 404 | `"Quarantine record not found."` |
| 409 | `"Not in quarantine (status: <status>)."` · `"File was permanently deleted from quarantine."` · `"Quarantined file is missing."` · `"Another quarantine action is in progress. Try again."` |
| 500 | `"Delete failed: could not remove file."` · `"Unexpected error. See server log."` |

Restore also refuses deleted records with 409 `"File was permanently deleted from quarantine."`. Event kind `delete_quarantine`, steps: `verifying record` → `deleting file` → `verified gone` → `op_end`.

#### 🔎 `GET /api/quarantine/list?limit=200`
`{"ok": true, "items": [{id, ts, pid, process_name, original_path_redacted, sha256_short, status, restored_at, deleted_at, is_simulated, note}]}`. `status`: `quarantined` | `restored` | `deleted` | `dry_run`.

### 3.4 Stop process

#### `POST /api/process/stop`: **not implemented**
`capabilities.features.stop_process` is `false`. Calling it returns FastAPI's `404 {"detail": "Not Found"}`. Don't show a "Stop" button. Quarantine stops the process as part of its flow.

### 3.5 Geofence

#### 🔎 `GET /api/geofence/preview?country_code=CN[&scope=observed]`
```json
{
  "ok": true, "scope": "observed", "country_code": "CN", "country_name": "China",
  "mode": "enforced", "mode_reason": "ENFORCE_FIREWALL is true and running as administrator",
  "already_blocked": false, "ip_count": 2, "ips": ["1.0.0.5", "1.0.0.6"], "recent_ip_count": 1,
  "skipped_counts": { "gateway/DNS/never-block host": 1 },
  "real_connections_affected": 3, "simulated_connections_affected": 1,
  "ttl_minutes": 30.0, "expires_at_if_applied": "2026-11-15T12:00:00+00:00",
  "command_display": "New-NetFirewallRule -Name GeoTrench-CN -Group GeoTrench -Direction Outbound -Action Block -RemoteAddress 1.0.0.5, 1.0.0.6",
  "notes": ["GeoIP is approximate; sites on shared CDNs in this country may also be affected.",
            "Existing connections to these IPs will be reset."]
}
```
`ips` (and `ip_count`) cover servers in that country your apps are connected to **now or saw in the last 15 minutes**; `recent_ip_count` is how many of them are from that recent memory rather than live connections.
Errors: **400** `"Invalid country code."`, **400** `"Invalid scope."`. Notes may also include `"No real connections to this country right now; the rule will be created when one appears."` or `"Existing connections may continue briefly; new connections are blocked."`.

#### ⚙️ `POST /api/geofence`
Body: `{"country_code": "CN", "confirm": true}`. `confirm` must be the JSON boolean `true`; `"true"` or `1` count as not confirmed. Optional `"scope"`; the default `"observed"` blocks the IPs this machine is actually talking to, and keeps adding new ones every few seconds.

| Status | Body |
|---|---|
| 200 | `{"ok": true, "message": "Geofenced China.", "country_code": "CN", "country_name": "China", "scope": "observed", "mode": "enforced", "ip_count": 2, "range_count": 0, "rule_name": "GeoTrench-CN", "rule_names": ["GeoTrench-CN"], "expires_at": "...", "command_display": "...", "reset_connections": 3, "op_id": "geofence-1"}` |
| 200 | message variants: `"Geofenced China. Dry run: no firewall rule sent."`, `"Geofenced China. No real IPs yet; rule will be created when one appears."` |
| 400 | `"Invalid country code."` (`op_id: null`) |
| 400 | `"Invalid scope."` (`op_id: null`) |
| 400 | `{"ok": false, "message": "Confirmation required.", "preview": {...}, "op_id": null}` |
| 409 | `"Region already geofenced."` |
| 409 | `"Region already geofenced. Undo first."` (different scope) |
| 500 | `"Firewall rule could not be created."` (region is **not** marked blocked) |
| 500 | `"Unexpected error. See server log."` |

#### ⚙️ `POST /api/undo_geofence`
Body: `{"country_code": "CN"}`, or **no body** to undo the most recent geofence (the `U` shortcut).

| Status | Body |
|---|---|
| 200 | `{"ok": true, "message": "Geofence removed for China.", "country_code": "CN", "mode": "enforced", "op_id": "undo_geofence-1"}` |
| 400 | `"Invalid country code."` (`op_id: null`) |
| 409 | `"Region is not geofenced."` (`op_id: null`) |
| 409 | `"No active geofence to undo."` (`op_id: null`) |
| 500 | `"Firewall rule could not be removed."` (stays blocked; retry) |

#### 🔎 `GET /api/geofence/state` (poll every ~5 s while the panel is visible)
```json
{
  "ok": true, "mode": "enforced", "mode_reason": "...", "is_admin": true, "enforce_firewall": true,
  "ttl_minutes": 30.0, "kill_on_geofence": false, "reset_connections_enabled": true,
  "sync_seconds": 5.0, "last_sync_at": "2026-11-15T08:22:01+00:00", "last_sync_ms": 7.7, "sync_errors": [],
  "blocked": [{ "country_code": "CN", "country_name": "China", "scope": "observed", "range_count": 0,
                "rule_names": ["GeoTrench-CN"], "since": "...", "expires_at": "...", "seconds_remaining": 1742,
                "ip_count": 3, "mode": "enforced", "rule_present": true,
                "blocked_ips": [{ "ip": "103.21.124.133", "city": "Mumbai", "country_code": "IN",
                                  "asn_org": "Example ISP", "process": "chrome.exe" }] }],
  "orphan_rules": [], "warnings": []
}
```
`rule_present` is `null` in dry run. `blocked_ips` (up to 50 per region) lists each blocked server with its location, provider, and the process that last used it (`null` if unknown). Use it to explain *what* is blocked, e.g. alongside the same process's connections to other countries, which keep working.

### 3.6 Live events

#### 🔎 `GET /api/events/stream` (Server-Sent Events)
- `Content-Type: text/event-stream`. The first line is `retry: 2000`.
- **Resume:** send the `Last-Event-ID` header (EventSource does this automatically on reconnect) or `?last_id=<id>`. You get every buffered event newer than that id. Without either, the stream starts **after the newest** event.
- **Frames:** `id: <id>\nevent: <type>\ndata: <event JSON>\n\n`. Event types are `op_start`, `op_step`, `op_end`, `connections_changed`.
- A `: ping` comment every 15 s keeps proxies open.
- The stream ends when the server stops; EventSource reconnects by itself.

#### 🔎 `GET /api/events/recent?limit=50` (max 500)
JSON list, **newest last**. Use it for the first paint, then subscribe with `last_id` = the last id you got.

#### 🔎 `GET /api/ops/{op_id}`
`{"ok": true, "op_id": "quarantine-3", "events": [...]}` with every buffered event of that operation, or **404** `{"ok": false, "message": "Operation not found."}` once it has aged out of the 500-event buffer.

---

## 4. Event schema

```json
{
  "id": 42,
  "ts": "2026-11-15T12:01:02.345+00:00",
  "type": "op_step",
  "op_id": "quarantine-3",
  "kind": "quarantine",
  "target": { "conn_id": "3f9a1c0b7e2d" },
  "is_simulated": false,
  "step": "hashing",
  "message": "Fingerprint recorded.",
  "status": "ok",
  "elapsed_ms": 812.4,
  "data": { "sha8": "1a2b3c4d" }
}
```
- `type`: `op_start` | `op_step` | `op_end` | `connections_changed`.
- `kind`: `quarantine` | `restore` | `geofence` | `undo_geofence` | `sync` (`stop_process` is reserved, not used).
- `target`: any of `conn_id`, `country_code`, `manifest_id`.
- `status`: `running` | `ok` | `failed`. `op_end` has `step` `"done"` (ok) or `"failed"`.
- `op_id` is `"<kind>-<n>"`. `n` counts up per kind since the server started.
- `data` holds only small values: `sha8`, `rule_name`, `ip_count`, `reset_count`, `manifest_id`, `sha256_short`.
- `connections_changed` has `op_id: null`, and `message` names the reason (`quarantine`, `restore`, `geofence`, `undo_geofence`, `sync`).

### Steps per kind (in the order the backend actually runs them)

| kind | steps |
|---|---|
| `quarantine` | `verifying target` → `hashing` (`data.sha8`) → `stopping process` → `process stopped` → `moving to quarantine` → `verified` (original gone + quarantined copy present) → `op_end` |
| `restore` | `verifying record` → `checking hash` (`data.sha8`) → `moving back` → `verified` (file back at its original location) → `op_end` |
| `geofence` | `collecting IPs` (`data.ip_count`) → `applying rule` (`data.rule_name`) → `rule applied` → `resetting connections` (`data.reset_count`) → `verified` (rule present, or `"Dry run: rule not sent."`) → `op_end` |
| `undo_geofence` | `removing rule` → `verified gone` → `op_end` |
| `sync` | one step: `ttl expired` · `new IPs added` (`data.ip_count`) · `orphan removed` (`data.rule_name`) |

A step can appear twice: first `running`, then `ok` or `failed`. A failure always produces one `failed` step whose `message` is exactly the HTTP response message, followed by `op_end` with `status: failed`.

### Example sequences

**Quarantine, success (real):**
```
op_start  quarantine-3  running
op_step   verifying target      running  "Checking the connection and its process."
op_step   verifying target      ok       "Target verified."
op_step   hashing               running  "Fingerprinting the program file."
op_step   hashing               ok       "Fingerprint recorded."            data {sha8}
op_step   stopping process      running  "Stopping the process."
op_step   process stopped       ok       "Process stopped."
op_step   moving to quarantine  running  "Moving the program file to quarantine."
op_step   moving to quarantine  ok       "File moved."
op_step   verified              ok       "Original is gone and the quarantined copy is present."
op_end    done                  ok       "Quarantined and stopped."         data {manifest_id, sha256_short}
connections_changed                      "quarantine"
```

**Quarantine, protected refusal:**
```
op_start  quarantine-4  running
op_step   verifying target  running  "Checking the connection and its process."
op_step   verifying target  failed   "Safety Override: Cannot delete OS file."
op_end    failed            failed   "Safety Override: Cannot delete OS file."
```

**Quarantine, simulated dry run** (`is_simulated: true` on every event):
```
op_start  quarantine-5  running
op_step   verifying target  running  "Checking the connection and its process."
op_step   verifying target  ok       "Simulated quarantine: no files were touched."
op_end    done              ok       "Simulated quarantine: no files were touched."   data {manifest_id}
connections_changed                  "quarantine"
```

**Geofence, failure:**
```
op_start  geofence-2  running
op_step   collecting IPs  ok       "2 public IPs seen for China."   data {ip_count: 2}
op_step   applying rule   running  "Sending the firewall rule."      data {rule_name: "GeoTrench-CN"}
op_step   applying rule   failed   "Firewall rule could not be created."
op_end    failed          failed   "Firewall rule could not be created."
```

---

## 5. UI wiring guide

1. **Subscribe first:** open the `EventSource` on `/api/events/stream` **before** calling any action, so you don't miss the first steps. For the first paint, call `/api/events/recent` and subscribe with `?last_id=<last id>`.
2. **Match events to the selected item** by `target.conn_id` / `target.country_code` / `target.manifest_id`, or by the `op_id` returned from the action call. Both work; the response can arrive after the first events.
3. **On `connections_changed`,** refetch `/api/connections`, and `/api/geofence/state` or `/api/quarantine/list` if those panels are open.
4. **Show server messages verbatim** (both responses and step messages). Don't rephrase safety messages.
5. **Simulated items must show a SIMULATED label** (`is_simulated: true` on connections, list items and events).
6. **Geofence is two-step:** `GET /api/geofence/preview`, show `notes`, `ips`, `real_connections_affected` and `mode`, then `POST /api/geofence` with `confirm: true` only after the user confirms.
7. **Disable action buttons** for a target while an op for that target is running (between `op_start` and `op_end`). The backend also serializes quarantine and restore and returns 409 if busy.
8. **Use `/api/capabilities`** to hide unavailable features (`stop_process`) and to label dry-run mode.
9. **Protected items:** show a lock when `is_protected` is true, but still let the server refuse, and display its 403 message.

### Minimal JS

```js
const API = "http://127.0.0.1:8000";

// fetch wrapper -> {ok, status, data, message}
export async function api(path, { method = "GET", body } = {}) {
  try {
    const res = await fetch(API + path, {
      method,
      headers: body ? { "Content-Type": "application/json" } : undefined,
      body: body ? JSON.stringify(body) : undefined,
    });
    let data = null;
    try { data = await res.json(); } catch { /* empty body */ }
    const ok = res.ok && data?.ok !== false;
    const message = data?.message ?? (Array.isArray(data?.detail) ? "Invalid request." : data?.detail) ?? `HTTP ${res.status}`;
    return { ok, status: res.status, data, message };
  } catch {
    return { ok: false, status: 0, data: null, message: "Backend not reachable." };
  }
}

// event stream with resume + reconnect
export function subscribe(onEvent, { lastId } = {}) {
  let es, closed = false, last = lastId ?? null, retry = 1000;
  const open = () => {
    es = new EventSource(API + "/api/events/stream" + (last != null ? `?last_id=${last}` : ""));
    for (const type of ["op_start", "op_step", "op_end", "connections_changed"]) {
      es.addEventListener(type, (e) => { last = Number(e.lastEventId); retry = 1000; onEvent(JSON.parse(e.data)); });
    }
    es.onerror = () => {               // server stopped or network blip: reopen with backoff
      es.close();
      if (!closed) setTimeout(open, retry = Math.min(retry * 2, 15000));
    };
  };
  open();
  return () => { closed = true; es?.close(); };
}

// usage
const stop = subscribe((ev) => {
  if (ev.type === "connections_changed") refreshConnections();
  else updateOpProgress(ev.op_id, ev);          // or match ev.target.conn_id
});
const r = await api("/api/quarantine", { method: "POST", body: { conn_id: selected.id } });
if (!r.ok) showError(r.message);                // verbatim
```

---

## 6. Known limitations

- **GeoIP is approximate.** Many cloud and CDN IPs resolve only to a country (`city: null`), and some locations are country centroids.
- **CDN and anycast:** blocking a country also blocks CDN servers located there for every site that uses them. Anycast IPs (e.g. `1.1.1.1`) have no single location and are never blocked.
- **VPNs and proxies bypass geofencing:** traffic exits wherever the VPN server is.
- **Observed scope only blocks IPs that have been seen.** The first connection to a new IP gets through; the background sync adds it within `sync_seconds` (default 5 s) and resets the connection. A page that already loaded stays on screen until it's reloaded.
- **A hard kill** (Task Manager, `taskkill /F`, power loss) skips cleanup. Firewall rules stay until the next start, which removes them automatically.
- **The event buffer holds 500 events in memory.** It's lost on restart, and `/api/ops/{op_id}` returns 404 once an op ages out.
- **`POST /api/process/stop` is not implemented.**
