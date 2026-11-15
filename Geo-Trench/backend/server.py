"""Geo-Trench backend. Source of truth for all security decisions."""
import ctypes
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

import ancestry
import config
import connections
import db
import geo
import quarantine
import scenarios

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("geotrench")


def is_admin() -> bool:
    """True only on Windows when running elevated. Never raises."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # AttributeError on non-Windows, OSError on odd shells
        return False


def enforcement_enabled() -> bool:
    return config.ENFORCE_FIREWALL and is_admin()


@asynccontextmanager
async def lifespan(app: FastAPI):
    admin = is_admin()
    log.info("Admin privileges: %s", "YES" if admin else "NO (run from an Administrator terminal for enforcement)")
    if enforcement_enabled():
        log.info("Firewall mode: ENFORCING (real Windows firewall rules will be created)")
    else:
        reason = "ENFORCE_FIREWALL=false" if not config.ENFORCE_FIREWALL else "not running as admin"
        log.info("Firewall mode: DRY-RUN (%s)", reason)
    for label, path in (("City", config.MAXMIND_CITY_PATH), ("ASN", config.MAXMIND_ASN_PATH)):
        log.info("MaxMind %s DB: %s (%s)", label, "FOUND" if path.is_file() else "MISSING", path)

    geo.init()
    if geo.geoip_is_fallback:
        log.warning("GeoIP: FALLBACK mode (City DB not loaded; using built-in city table)")
    elif not geo.readers_loaded():
        log.warning("GeoIP: LIVE, but ASN DB not loaded (asn_org will be null)")
    else:
        log.info("GeoIP: LIVE (City + ASN loaded)")
    origin = geo.get_origin()
    log.info("Origin: %s (%s, %s)", origin["name"], origin["lat"], origin["lng"])
    log.info("Demo mode: %s", "ON" if config.DEMO_MODE else "OFF")

    try:
        path = db.init_db()
        log.info("Database: %s", path)
        removed = db.purge_older_than()
        log.info("Retention purge (%d days): removed %s", config.RETENTION_DAYS, removed)
        log.info("Database rows: %s", db.row_counts())
        log.info("Blocked regions (from geofence log): %s", db.get_blocked_regions() or "none")
    except Exception as e:
        log.error("Database unavailable, running without audit log: %s", e)
    yield
    db.close()
    geo.close()


app = FastAPI(title="Geo-Trench", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "is_admin": is_admin(),
        "demo_mode": config.DEMO_MODE,
        "enforcement_enabled": enforcement_enabled(),
        "geoip_loaded": geo.readers_loaded(),
        "geoip_fallback": geo.geoip_is_fallback,
    }


@app.get("/api/geo/test")
def geo_test(ip: str):
    kind = geo.classify_ip(ip)
    if kind == "invalid":
        return {"ip": ip, "result": None, "message": f"'{ip}' is not a valid IP address"}
    if kind != "public":
        return {"ip": ip, "result": None, "message": f"{ip} is a {kind} address and has no geolocation"}
    result = geo.geolocate(ip)
    if result is None:
        return {"ip": ip, "result": None, "message": f"No location found for {ip}"}
    if result["anycast"]:
        return {
            "ip": ip,
            "result": result,
            "message": f"{ip} is anycast ({result['anycast_provider']}); served from many locations, so no single position",
        }
    return {"ip": ip, "result": result, "fallback": geo.geoip_is_fallback}


@app.get("/api/origin")
def origin():
    return geo.get_origin()


@app.get("/api/process/test")
def process_test(pid: int):
    return ancestry.public_view(ancestry.get_process_info(pid))


@app.get("/api/connections")
def get_connections():
    return connections.get_snapshot()


@app.post("/api/quarantine")
def post_quarantine(req: quarantine.QuarantineRequest):
    status, body = quarantine.quarantine_connection(req.conn_id)
    return JSONResponse(status_code=status, content=body)


@app.post("/api/quarantine/restore")
def post_quarantine_restore(req: quarantine.RestoreRequest):
    status, body = quarantine.restore_quarantined(req.manifest_id)
    return JSONResponse(status_code=status, content=body)


@app.get("/api/quarantine/list")
def quarantine_list(limit: int = 200):
    try:
        return {"ok": True, "items": db.list_quarantine_records(limit)}
    except Exception:
        log.exception("quarantine list failed")
        return JSONResponse(
            status_code=500,
            content={"ok": False, "message": "Unexpected error. See server log."},
        )


@app.get("/api/audit")
def audit(limit: int = 50):
    try:
        return db.get_audit_events(limit)
    except Exception as e:
        log.warning("Audit read failed: %s", e)
        return []


@app.get("/api/scenarios/test")
def scenarios_test():
    return [ancestry.public_view(c) for c in scenarios.get_planted_connections()]
