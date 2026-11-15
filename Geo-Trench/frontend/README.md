# Geo-Trench Frontend

React + Vite frontend for Geo-Trench. It only renders data and sends requests; the backend
(`../backend`) makes every security decision.

## Run

```powershell
cd Geo-Trench\frontend
npm install        # first time only
npm run dev
```

Open **http://localhost:5173**. Use `localhost`, not `127.0.0.1`: the backend's CORS only
allows that exact address. The dev server is pinned to port 5173 (`strictPort`) for the same reason.

The backend must be running at `http://127.0.0.1:8000` (see `../TESTING.md`). To point
elsewhere, copy `.env.example` to `.env`, set `VITE_API_URL`, and restart `npm run dev`.

All API calls live in `src/api.js`.

## Databricks incident globe

The overview defaults to **Databricks incidents**. Configure the backend OAuth
credentials using [the Databricks setup guide](../backend/DATABRICKS.md). Each row
supplies its own source and destination coordinates. Severity determines the arc
color; repeated routes receive small stable offsets. Search by IP or description,
filter severity, and select a row for details. The globe draws up to 180 routes,
including the selected incident, while the list covers the full loaded snapshot.

GET /api/incidents is polled every 3 seconds; the backend caches results and queries
the warehouse at most every 30 seconds by default while clients poll.

**Device traffic** retains the existing local monitoring and quarantine workflow.
Activity and Quarantine tabs refer to device monitoring, not Databricks incidents.

---



## Backend API contract

### Exists now

#### Polled on a timer

| Request | Suggested interval | Powers |
|---|---|---|
| `GET /api/connections` | every 2–3 s | Globe arcs, threat list, stats bar, anycast panel (Device traffic view) |
| `GET /api/audit?limit=50` | every 3–5 s | Event ticker |
| `GET /api/health` | on load, then ~30 s | Status badge (admin, enforcing vs dry-run, GeoIP live/fallback) and "backend down" banner |

#### Fetched once

| Request | Powers |
|---|---|
| `GET /api/origin` | Home point on the globe. It's also included in every `/api/connections` response, so this call is optional. |

#### User-triggered

| Request | Body | Responses to handle |
|---|---|---|
| `POST /api/quarantine` | `{"conn_id": "abc123def456"}` only | `200` success (real, or `simulated: true`) · `403` `code: "PROTECTED"`: show the lock and the "Safety Override" message · `404` connection closed · `409` process changed or another quarantine is running · `422` bad body · `500` `{ok:false, message}` |
| `GET /api/quarantine/list` | n/a | Quarantine panel: `{ok, items: [...]}`, no real paths |

**Debug only (not for the UI):** `/api/geo/test`, `/api/process/test`, `/api/scenarios/test`.

### Planned (not built yet)

| Request | Why |
|---|---|
| `POST /api/geofence/block` `{country_code}` | Block a region (currently only possible through the database directly) |
| `POST /api/geofence/unblock` `{country_code}` | Undo a block |
| `GET /api/geofence` | Current blocked regions plus history (`stats.blocked_regions` already gives the current set) |
| `POST /api/quarantine/restore` `{manifest_id}` | Restore button on the quarantine panel |
| `POST /api/agent/explain` `{conn_id}` | Plain-English AI explanation |
| `POST /api/agent/actions/{id}/decide` `{approve or reject}` | Approve or reject an agent proposal |

---

## `/api/connections` response shape

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
      "local_ip": "192.168.1.50", "local_port": 49731,
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

Connections are sorted unsafe first, then by `id`. `/api/audit` returns a newest-first list of
`{ts, type, severity, message, ref_id}`.

---

## Rules for the frontend

- **Send ids, never targets.** Actions send `conn_id`, `manifest_id`, or `country_code`, never a PID or a file path. The server rejects anything else (`422`).
- **The lock is cosmetic.** Show a lock when `is_protected` is true, but always handle the `403`; the server re-checks every request.
- **Expect missing coordinates.** Anycast connections arrive in the separate `anycast` list and can't be placed on the globe. Many `city` values are `null` (country-level location only).
- **Key on `id`.** Connection ids are stable across polls; use them as React keys and to animate arcs in and out.
- **Show `warnings`.** If the `warnings` array in `/api/connections` isn't empty, display it (e.g. database down, not running as admin).
- **Don't overlap polls.** The first poll can take ~600 ms, and some later ones are slower while the process cache refreshes. Wait for each request to finish before starting the next.
- **Simulated threats are labelled.** `is_simulated: true` (negative PIDs) marks demo threats; quarantining them is always a dry run.
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

At implementation time, backend/server.py does NOT register /api/quarantine or /api/quarantine/list, although the contract above describes them. The frontend includes their integration and reports unavailable endpoints honestly. No backend enforcement or filesystem behavior was added. Planned geofence, restore, and agent APIs are not called or exposed as working controls.

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
