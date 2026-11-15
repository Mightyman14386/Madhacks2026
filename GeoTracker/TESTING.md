# Testing GeoTracker

How to set up the backend on a fresh Windows machine and verify every feature built so far.
All commands are **PowerShell**. Nothing here modifies your firewall or files: the planted
threats are simulated, and firewall enforcement is off by default (`ENFORCE_FIREWALL=false`).

> **Current scope:** backend only (FastAPI). There is no frontend yet; everything is tested
> with `irm` (`Invoke-RestMethod`) against `http://127.0.0.1:8000`.

---

## 1. Prerequisites

| Requirement | Notes |
|---|---|
| Windows 10/11 | The admin check and protected paths are Windows-specific. |
| Python 3.11+ | Check with `py --version`. 3.13 also works. |
| MaxMind GeoLite2 files (optional) | `GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb`. Without them the backend runs in **fallback mode** (see below). |

### Getting the MaxMind files
1. Create a free account at <https://www.maxmind.com/en/geolite2/signup>.
2. Download **GeoLite2 City** and **GeoLite2 ASN** (the `.mmdb` format, `.tar.gz` archives).
3. Extract and copy both `.mmdb` files into `GeoTracker/backend/data/`.

These files are licensed by MaxMind and are git-ignored. Do not commit them.

---

## 2. Setup

From the repo root:

```powershell
cd GeoTracker\backend
py -3 -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
```

If `Activate.ps1` is blocked: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`, then activate again.

### Configuration (`backend/.env`)

| Variable | Default | Meaning |
|---|---|---|
| `DEMO_MODE` | `true` | Adds 4 simulated threats to `/api/connections`. |
| `ENFORCE_FIREWALL` | `false` | Real firewall rules only if `true` **and** running as Administrator. Otherwise dry-run. |
| `RULE_TTL_MINUTES` | `30` | Reserved for firewall rules (not used yet). |
| `MAXMIND_CITY_PATH` / `MAXMIND_ASN_PATH` | `data/GeoLite2-*.mmdb` | Relative to `backend/`. |
| `ORIGIN_LAT` / `ORIGIN_LNG` / `ORIGIN_NAME` | Madison, WI | This machine's point on the globe. |
| `RETENTION_DAYS` | `7` | Audit rows older than this are purged at startup. |

---

## 3. Unit tests (no server needed)

Run from `GeoTracker\backend` with the venv active:

```powershell
python test_threats.py
python test_db.py
```

| Script | Expected last line | Covers |
|---|---|---|
| `test_threats.py` | `13/13 passed` | Threat rules, severities, false-positive control, all 4 planted scenarios |
| `test_db.py` | `12/12 passed` | SQLite upserts, geofence replay, retention purge, no raw paths stored, audit feed |

`test_db.py` uses a temporary database and never touches `backend/geotrench.db`.

Both scripts exit with code `1` on any failure.

---

## 4. Start the server

Use a terminal opened with **Run as Administrator** for the full picture (non-admin works, but
some processes show as `unknown`).

```powershell
cd GeoTracker\backend
.\venv\Scripts\Activate.ps1
python -m uvicorn server:app --port 8000
```

### Expected startup logs

```
Admin privileges: YES
Firewall mode: DRY-RUN (ENFORCE_FIREWALL=false)
MaxMind City DB: FOUND (...\backend\data\GeoLite2-City.mmdb)
MaxMind ASN DB: FOUND (...\backend\data\GeoLite2-ASN.mmdb)
GeoIP: LIVE (City + ASN loaded)
Origin: Madison, WI (43.0731, -89.4012)
Demo mode: ON
Database: ...\backend\geotrench.db
Retention purge (7 days): removed {...}
Database rows: {...}
Blocked regions (from geofence log): none
```

Without the MaxMind files you'll see `MISSING` and `GeoIP: FALLBACK mode`. That is expected.

Interactive API docs are at <http://127.0.0.1:8000/docs>.

> Opening `http://127.0.0.1:8000/` in a browser returns **404**. That's normal: there is no root page.

---

## 5. Endpoint checks

Run these in a **second** terminal while the server is running.

### 5.1 Health

```powershell
irm http://127.0.0.1:8000/api/health
```

| Field | Expected |
|---|---|
| `status` | `ok` |
| `is_admin` | `True` in an Administrator terminal |
| `demo_mode` | `True` |
| `enforcement_enabled` | `False` (unless `ENFORCE_FIREWALL=true` and admin) |
| `geoip_loaded` | `True` if both `.mmdb` files opened |
| `geoip_fallback` | `False` if the City file opened |

### 5.2 GeoIP

```powershell
irm "http://127.0.0.1:8000/api/geo/test?ip=128.104.153.1"   # Madison, US (University of Wisconsin)
irm "http://127.0.0.1:8000/api/geo/test?ip=202.12.29.205"   # Brisbane, AU (APNIC)
irm "http://127.0.0.1:8000/api/geo/test?ip=200.160.4.6"     # São Paulo, BR
irm "http://127.0.0.1:8000/api/geo/test?ip=1.1.1.1"         # anycast (Cloudflare DNS), no coordinates
irm "http://127.0.0.1:8000/api/geo/test?ip=192.168.1.10"    # "is a private address"
irm "http://127.0.0.1:8000/api/geo/test?ip=banana"          # "is not a valid IP address"
irm http://127.0.0.1:8000/api/origin                        # Madison, WI
```

**Note:** `city` being `null` is normal for many cloud/CDN IPs (Google, GitHub, etc.). MaxMind
only knows the country for those, and returns a country-level default point.

### 5.3 Process ancestry

```powershell
irm "http://127.0.0.1:8000/api/process/test?pid=$PID"     # your terminal: ... -> powershell.exe
irm "http://127.0.0.1:8000/api/process/test?pid=4"        # System: exe null, no error
irm "http://127.0.0.1:8000/api/process/test?pid=999999"   # name "unknown", ancestry ["unknown"]
```

Check: usernames in paths appear as `C:\Users\<user>\...`, and there is **no** `raw_exe` field.

### 5.4 Demo scenarios

```powershell
irm http://127.0.0.1:8000/api/scenarios/test | ConvertTo-Json -Depth 5
```

Expect 4 simulated connections, all `unsafe`:

| PID | Process | Location | Severity | Protected |
|---|---|---|---|---|
| -1001 | updater.exe (Word → cmd) | Moscow, RU | critical | no |
| -1002 | payload.exe (PowerShell) | Shenzhen, CN | medium | no |
| -1003 | svc_host32.exe (Temp folder) | Lagos, NG | high | no |
| -1004 | rundll32.exe (Excel) | Bucharest, RO | critical | **yes** (under `C:\Windows`) |

### 5.5 Live connections

```powershell
$r = irm http://127.0.0.1:8000/api/connections
$r.stats
$r.generated_ms
$r.warnings
$r.connections | Select-Object -First 10 status, severity, is_protected, is_simulated, process_name, remote_ip, city, country_code | Format-Table
$r.connections | Where-Object status -eq 'unsafe' | Format-List process_name, severity, reasons
$r.anycast
```

What to look for:
- The 4 planted threats at the top (`is_simulated: True`), followed by your real traffic.
- Normal apps (Chrome, VS Code, Teams…) should be `safe`.
- `generated_ms` is usually under ~50 on repeat calls. The first call can take several hundred ms while the process cache warms up.
- `warnings` is empty.

Privacy check: this must print `False`:

```powershell
($r | ConvertTo-Json -Depth 6) -match 'raw_exe|cmdline'
```

Stable IDs: the same connection keeps its `id` and `first_seen` across calls:

```powershell
$a = irm http://127.0.0.1:8000/api/connections; $b = irm http://127.0.0.1:8000/api/connections
$a.connections[0].id; $b.connections[0].id
```

### 5.6 Audit feed

```powershell
irm "http://127.0.0.1:8000/api/audit?limit=10" | Format-Table ts, type, severity, message -AutoSize
```

After at least one `/api/connections` call, expect 4 `threat_detected` events marked `(demo)`.
Messages never contain file paths.

---

## 6. Geofence and persistence

There is no HTTP endpoint for blocking yet, so write the event directly to the database.
This is safe while the server is running.

**Block Romania** (hides the Bucharest demo threat):

```powershell
python -c "import db; db.init_db(); db.append_geofence_event('block','RO',['203.0.113.150'],'GT-RO',False,None,'manual test'); print(db.get_blocked_regions())"
(irm http://127.0.0.1:8000/api/connections).stats
```

Expect `['RO']`, then `hidden_by_geofence: 1`, `blocked_regions: {RO}`, `unsafe: 3`.

**Restart the server** (Ctrl+C, then start it again) and verify:
- Startup log: `Blocked regions (from geofence log): ['RO']` and non-zero row counts.
- `(irm http://127.0.0.1:8000/api/connections).stats` still shows `hidden_by_geofence: 1`.
- `irm http://127.0.0.1:8000/api/audit` still lists the earlier threats with their **original** timestamps, plus `Blocked traffic to RO (dry-run)`.

**Unblock.** Undo appends a row; nothing is ever deleted:

```powershell
python -c "import db; db.init_db(); db.append_geofence_event('unblock','RO',[],'GT-RO',False,None,'manual test'); print(db.get_blocked_regions(), db.row_counts()['geofence_log'])"
```

Expect `[] 2`. Bucharest reappears in `/api/connections` within about a second.

---

## 7. Optional checks

**Fallback GeoIP mode** (without removing files):

```powershell
$env:MAXMIND_CITY_PATH = "data/nope.mmdb"
python -m uvicorn server:app --port 8000
```

Expect `GeoIP: FALLBACK mode`, `geoip_fallback: True` in `/api/health`, and the same IP always
mapping to the same built-in city across restarts. Undo with `Remove-Item Env:MAXMIND_CITY_PATH`.

**Demo mode off:** set `DEMO_MODE=false` in `.env` and restart. `/api/scenarios/test` returns `[]`
and `/api/connections` shows only real traffic.

**Ancestry from the command line:**

```powershell
python ancestry.py
```

Prints the launch chain of the Python process and its parent, with usernames redacted.

---

## 8. Reset

Stop the server, then:

```powershell
Remove-Item geotrench.db*
```

This deletes the audit database (`geotrench.db`, `-wal`, `-shm`). It is recreated on next start.

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `Activate.ps1 cannot be loaded` | `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` |
| `Admin privileges: NO` | Open PowerShell with **Run as Administrator**. |
| `MaxMind ... MISSING` | Put both `.mmdb` files in `backend/data/` with the exact names, or fix the paths in `.env`. |
| Many processes show `unknown` | Not running as Administrator. |
| `city: null` for some IPs | Normal: MaxMind only has country-level data for many cloud/CDN ranges. |
| Anycast IP (e.g. `1.1.1.1`) not on the globe | By design: it appears in the `anycast` list instead, because it has no single location. |
| `warnings` mentions the database | The DB failed to open; `/api/connections` still works without recording findings. Check file permissions on `backend/`. |
| Port 8000 in use | Run with `--port 8001` and adjust the URLs. |
