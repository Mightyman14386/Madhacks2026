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

---

## Backend API contract

### Exists now

#### Polled on a timer

| Request | Suggested interval | Powers |
|---|---|---|
| `GET /api/connections` | every 2–3 s | Globe arcs, threat list, stats bar, anycast panel (the main feed) |
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
