# GeoTracker Frontend

React + Vite frontend for GeoTracker. It only renders data and sends requests; the backend
(`../backend`) makes every security decision.

## Run

```powershell
cd GeoTracker\frontend
npm install        # first time only
npm run dev
```

Open **http://localhost:5173**. Use `localhost`, not `127.0.0.1`: the backend's CORS only
allows that exact address. The dev server is pinned to port 5173 (`strictPort`) for the same reason.

The backend must be running at `http://127.0.0.1:8000` (see `../TESTING.md`). To point
elsewhere, copy `.env.example` to `.env`, set `VITE_API_URL`, and restart `npm run dev`.

All API calls live in `src/api.js`.

## Databricks incident globe

The overview defaults to **Security insights**. Configure the backend OAuth
credentials using [the Databricks setup guide](../backend/DATABRICKS.md). Each row
supplies its own source and destination coordinates. Severity determines the arc
color; repeated routes receive small stable offsets. Search by IP or description,
filter severity, and select a row for details. The globe draws up to 180 routes,
including the selected incident, while the list covers the full loaded snapshot.

GET /api/incidents is polled every 3 seconds; the backend caches results and queries
the warehouse at most every 30 seconds by default while clients poll.

**Device traffic** retains the existing local monitoring and quarantine workflow.
Activity and Quarantine tabs refer to device monitoring, not Security insights.

---



## Backend API contract

Everything the backend exposes on `http://127.0.0.1:8000`. The frontend sends only ids and country
codes. It never receives local IPs, gateway/DNS addresses, real file paths, or command lines.

### Live data (polled)

| Request | Suggested interval | Powers |
|---|---|---|
| `GET /api/connections` | every 2–3 s | Device traffic: globe arcs, threat list, stats bar, anycast panel |
| `GET /api/audit?limit=50` | every 3–5 s | Event ticker |
| `GET /api/geofence/state` | every 5 s (while the geofence panel is visible) | Blocked regions, countdowns, sync health |
| `GET /api/quarantine/list` | when the Quarantine tab is open (~5 s) | Quarantine panel |
| `GET /api/incidents` | every 3 s | Databricks incident globe (backend queries the warehouse at most every 30 s) |
| `GET /api/health` | on load, then ~30 s | Status badge (admin, enforcing vs dry-run, GeoIP live/fallback) and "backend down" banner |
| `GET /api/origin` | once (optional) | Home point; also included in every `/api/connections` response |

#### `GET /api/connections`

```jsonc
{
  "origin": { "lat": 43.0731, "lng": -89.4012, "name": "Madison, WI" },
  "connections": [
    {
      "id": "3f9a1c0b7e2d",            // stable across polls; use as React key
      "pid": 1234,                      // negative for simulated demo threats
      "process_name": "chrome.exe",
      "exe": "C:\\Program Files\\...",  // already redacted (C:\Users\<user>\...)
      "ancestry": ["explorer.exe", "chrome.exe"],
      "ancestry_detail": [{ "pid": 1, "name": "explorer.exe", "exe": "..." }],
      "local_port": 49731,              // local_ip is never returned (privacy)
      "remote_ip": "142.250.80.46", "remote_port": 443,
      "country_code": "US", "country_name": "United States",
      "city": null,                     // often null for cloud/CDN IPs
      "asn_org": "Google LLC",
      "lat": 37.751, "lng": -97.822,
      "status": "safe",                 // "safe" | "unsafe"
      "severity": "low",                // "low" | "medium" | "high" | "critical"
      "rules_fired": [],
      "reasons": [],                    // plain-English strings
      "is_protected": true,
      "is_simulated": false,
      "first_seen": "2026-11-15T04:22:36+00:00"
    }
  ],
  "anycast": [
    { "id": "...", "pid": 0, "process_name": "...", "remote_ip": "1.1.1.1", "remote_port": 443,
      "provider": "Cloudflare DNS", "asn_org": "Cloudflare, Inc.",
      "status": "safe", "severity": "low", "rules_fired": [], "reasons": [] }
  ],
  "stats": { "total": 25, "safe": 21, "unsafe": 4, "anycast": 0,
             "hidden_by_geofence": 0, "blocked_regions": [] },
  "geoip_fallback": false,
  "truncated": false,
  "warnings": [],
  "generated_ms": 34.2
}
```

Connections are sorted unsafe first, then by `id`. Geofenced countries are removed from
`connections` and counted in `stats.hidden_by_geofence`; the `anycast` list is unaffected.

#### `GET /api/audit?limit=50`

Newest-first list of `{ts, type, severity, message, ref_id}`. Messages are plain English and never
contain paths. Types:

- `threat_detected`
- `quarantine`, `quarantine_restore`, `quarantine_integrity`
- `geofence_block`, `geofence_unblock`, `geofence_update`, `geofence_failed`, `geofence_orphan`
- `agent_proposed`, `agent_decision`

#### `GET /api/geofence/state`

```jsonc
{
  "ok": true,
  "mode": "enforced",                 // "enforced" | "dry_run"
  "mode_reason": "ENFORCE_FIREWALL is true and running as administrator",
  "is_admin": true, "enforce_firewall": true,
  "ttl_minutes": 30, "kill_on_geofence": false, "reset_connections_enabled": true,
  "sync_seconds": 5, "last_sync_at": "2026-11-15T08:22:01+00:00", "last_sync_ms": 7.7,
  "sync_errors": [],                  // last 5 messages, no IPs
  "blocked": [
    { "country_code": "CN", "country_name": "China", "scope": "observed",
      "range_count": 0, "rule_names": ["GeoTrench-CN"],
      "since": "...", "expires_at": "...", "seconds_remaining": 1742,
      "ip_count": 3, "mode": "enforced",
      "rule_present": true }          // null in dry run
  ],
  "orphan_rules": [],
  "warnings": []
}
```

#### `GET /api/quarantine/list`

`{ok, items: [{id, ts, pid, process_name, original_path_redacted, sha256_short, status, restored_at, is_simulated, note}]}`.
`status` is `quarantined` | `restored` | `dry_run`. Never includes the real or quarantine path.

#### `GET /api/incidents`

```jsonc
{
  "incidents": [
    { "id": "incident-<hash>-1",
      "latitude_src": 0, "longitude_src": 0, "latitude_dest": 0, "longitude_dest": 0,
      "severity": "high",             // "low" | "medium" | "high" | "critical" | "unknown"
      "description": "...", "ip": "..." }
  ],
  "counts": { "high": 12 },
  "warnings": [], "truncated": false,
  "fetched_at": "...", "warehouse_id": "...", "table": "workspace.default.geospatial_incidents",
  "state": "ready",                   // "loading" | "refreshing" | "ready" | "error"
  "source": "databricks", "stale": false, "message": null
}
```

Returns **503** only while erroring before the first successful fetch; after that, errors come back
as `200` with `stale: true` and the last good snapshot.

#### `GET /api/health`

`{status, is_admin, demo_mode, enforcement_enabled, geoip_loaded, geoip_fallback}`.

### Actions (user-triggered)

| Request | Body | Responses to handle |
|---|---|---|
| `POST /api/quarantine` | `{"conn_id"}` only | `200 {ok, simulated, message, manifest_id[, sha256_short]}` · `403` `code: "PROTECTED"` "Safety Override: Cannot delete OS file." · `404` connection closed · `409` process changed / another action running · `422` bad body · `500` |
| `POST /api/quarantine/restore` | `{"manifest_id"}` | `200 {ok, message, manifest_id, file_name, restored_to, sha256_short}` · `400` simulated record · `403` protected destination / invalid quarantine path · `404` · `409` not in quarantine, file missing, file changed, folder gone, or target exists |
| `GET /api/geofence/preview?country_code=XX[&scope=observed]` | n/a | `200 {ok, scope, country_code, country_name, mode, mode_reason, already_blocked, ip_count, ips, skipped_counts, real_connections_affected, simulated_connections_affected, ttl_minutes, expires_at_if_applied, command_display, notes}` · `400` invalid code or scope |
| `POST /api/geofence` | `{"country_code", "confirm": true[, "scope"]}` | `200 {ok, message, country_code, country_name, scope, mode, ip_count, rule_name, rule_names, expires_at, command_display, reset_connections}` · `400` (with `preview` when `confirm` isn't exactly `true`) · `409` already geofenced · `500` firewall failure (region is not marked blocked) |
| `POST /api/undo_geofence` | `{"country_code"}` or empty (undoes the most recent) | `200 {ok, message, country_code, mode}` · `409` not geofenced / nothing to undo · `500` (stays blocked; retry) |

Every failure uses `{ok: false, message}`, sometimes with a `code` (e.g. `"PROTECTED"`).
`confirm` must be the JSON boolean `true`; `"true"` or `1` count as unconfirmed.

**Debug only (not for the UI):** `/api/geo/test`, `/api/process/test`, `/api/scenarios/test`.

### Not built yet

| Request | Why |
|---|---|
| `POST /api/agent/explain` `{conn_id}` | Plain-English AI explanation |
| `POST /api/agent/actions/{id}/decide` `{approve or reject}` | Approve or reject an agent proposal |

### Currently wired in `src/api.js`

`health`, `connections`, `audit`, `quarantine/list`, `quarantine`, `incidents`. Restore and the
geofence endpoints exist on the backend but aren't called by the UI yet.

---

## Rules for the frontend

- **Send ids, never targets.** Actions send `conn_id`, `manifest_id`, or `country_code`, never a PID or a file path. The server rejects anything else (`422`).
- **The lock is cosmetic.** Show a lock when `is_protected` is true, but always handle the `403`; the server re-checks every request.
- **Expect missing coordinates.** Anycast connections arrive in the separate `anycast` list and can't be placed on the globe. Many `city` values are `null` (country-level location only).
- **Key on `id`.** Connection ids are stable across polls; use them as React keys and to animate arcs in and out.
- **Show `warnings`.** If the `warnings` array in `/api/connections` isn't empty, display it (e.g. database down, not running as admin).
- **Don't overlap polls.** The first poll can take ~600 ms, and some later ones are slower while the process cache refreshes. Wait for each request to finish before starting the next.
- **Simulated threats are labelled.** `is_simulated: true` (negative PIDs) marks demo threats; quarantining them is always a dry run.
- **Geofence is backend-authoritative.** Always preview first and show `notes`; send `confirm: true` only after the user confirms. A geofenced country's connections disappear from `/api/connections` within about a second; read `/api/geofence/state` for countdowns and `mode` (dry run vs enforced).
- **Observed scope blocks after first contact.** New IPs in a geofenced country are added by the backend sync within `sync_seconds`; a page that already loaded stays on screen until it's reloaded.
- **CORS only allows `http://localhost:5173`.**

## Interactive dashboard

The frontend now provides a dark network observatory centered on a rotatable country-outline globe. It uses locally bundled D3 geographic projections and World Atlas 110m country boundaries (Natural Earth data). DM Sans and Space Grotesk fonts are bundled locally through Fontsource; no map service, API key, or runtime font CDN is required.

### Controls and views

- Drag the globe to rotate, or focus it and use arrow keys. Use the + / - buttons (or keys) to zoom. Rotate toggles automatic rotation; Reset restores the initial view. Reduced-motion preferences disable automatic movement and route particles.
- Select a glowing destination or a connection row to focus the globe and inspect backend findings, process ancestry, protection status, and endpoint details.
- Search by process, provider, country, or IP. Press / outside an input to focus search. Filter by backend-reported safe or unsafe status.
- Latest check shows the current snapshot. Session · 15m retains up to 2,000 observed connection IDs in memory for fifteen minutes while this page is open. Each record retains the origin from its observation. This is not persisted backend history.
- Activity shows the audit feed, with navigation to connections that are still in the latest snapshot. Pause stops connection and audit updates; it does not stop network traffic or backend enforcement.
- Anycast endpoints and missing coordinates are not assigned fabricated locations. A separate panel shows anycast endpoints, and map counts disclose unlocated connections.
- Export view downloads the filtered connection view as JSON. Executable paths and ancestry_detail are omitted; IP addresses and other visible endpoint metadata are included.
- Explore demo uses explicitly labeled synthetic TEST-NET endpoints, distinct from backend observations. The frontend cannot submit security actions in this mode.

### Backend safety and availability

All API calls stay in src/api.js. Connections, audit, and health use independent sequential polling loops with abort-on-unmount and request timeouts. A new request in a loop is scheduled only after the previous one finishes. Backend errors show a banner and preserve the last snapshot with its last-check time. Warnings, GeoIP fallback mode, truncation, administrator status, and enforcement mode are visible.

Quarantine requires a confirmation dialog and submits only {conn_id}. The frontend handles protected-process 403 Safety Override, 404 unavailable/closed connection, 409 conflict, 422 invalid request, backend failures, and simulated successes. Cosmetic locks do not authorize or prevent server-side checks.

The backend now registers /api/quarantine, /api/quarantine/list, /api/quarantine/restore, and the geofence endpoints described above. The frontend calls quarantine and the list, and still reports unavailable endpoints honestly if pointed at an older backend. Restore, geofence, and agent controls are not exposed in the UI yet.

Routes show the relationship between the device origin and an approximate remote location. The API does not contain measured traffic direction or physical network paths. Moving route particles are illustrative. Locations can be country-level, especially for cloud/CDN infrastructure.

### Verification

```powershell
npm test
npm run build
# In another terminal, keep npm run dev running at http://localhost:5173
npx playwright install chromium
npm run test:browser
```

If the repository's Paste Guard test browser is already present, the browser runner reuses it; otherwise install Chromium as above or set PLAYWRIGHT_BROWSERS_PATH. Playwright is development-only.

Unit tests cover coordinate validation, stable history updates, expiration, and bounds. Browser tests use synthetic API fixtures (not live security actions) and cover desktop/mobile layout, globe controls, selection, filtering, warnings, missing coordinates, export, unavailable endpoints, quarantine response statuses, demo action restrictions, backend outages, and non-overlapping polls. Screenshots are written to ignored test-results/.
