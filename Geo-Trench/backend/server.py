"""Geo-Trench backend. Source of truth for all security decisions."""
import asyncio
import atexit
import ctypes
import logging
from contextlib import asynccontextmanager, suppress

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

import ancestry
import config
import connections
import db
import geo
import geofence
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


# ---------------------------------------------------------------- exit cleanup
# Ctrl+C runs the lifespan shutdown below. Closing the console window, logging off, or a system
# shutdown kills the process without it, so a Windows console handler runs the same cleanup.
_CTRL_CLOSE_EVENT, _CTRL_LOGOFF_EVENT, _CTRL_SHUTDOWN_EVENT = 2, 5, 6
_console_handler = None  # keep a reference so the callback isn't garbage-collected


def _cleanup_on_exit(reason):
    try:
        result = geofence.shutdown_cleanup()
        log.info("Exit cleanup (%s): %s", reason, result)
    except Exception:
        log.exception("Exit cleanup failed (%s)", reason)


def _install_console_handler():
    global _console_handler
    try:
        handler_type = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_uint)

        def on_event(event):
            if event in (_CTRL_CLOSE_EVENT, _CTRL_LOGOFF_EVENT, _CTRL_SHUTDOWN_EVENT):
                _cleanup_on_exit(f"console event {event}")
                db.close()
                return True
            return False  # Ctrl+C / Ctrl+Break: let uvicorn shut down normally (lifespan cleanup)

        _console_handler = handler_type(on_event)
        ctypes.windll.kernel32.SetConsoleCtrlHandler(_console_handler, True)
    except Exception:
        log.warning("Could not install console close handler; cleanup will run on Ctrl+C only")


async def _geofence_sync_loop():
    """Runs geofence.sync_once every GEOFENCE_SYNC_SECONDS in a worker thread. Never dies."""
    while True:
        try:
            await asyncio.to_thread(geofence.sync_once)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("Geofence sync tick failed")
        await asyncio.sleep(max(1.0, float(config.GEOFENCE_SYNC_SECONDS)))


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
    # Startup sweep BEFORE the sync starts: OS rules from a previous run are removed and the log matches.
    try:
        log.info("Startup sweep: %s", geofence.startup_sweep())
    except Exception:
        log.exception("Startup sweep failed")

    _install_console_handler()
    atexit.register(geofence.atexit_sweep)  # last resort: firewall rules only
    log.info("Exit cleanup armed: GeoTrench firewall rules are removed when the server stops")

    sync_task = asyncio.create_task(_geofence_sync_loop())
    log.info("Geofence sync running every %ss", config.GEOFENCE_SYNC_SECONDS)
    try:
        yield
    finally:
        sync_task.cancel()
        with suppress(asyncio.CancelledError, Exception):
            await sync_task
        _cleanup_on_exit("server shutdown")
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


@app.get("/api/geofence/preview")
async def geofence_preview(country_code: str = "", scope: str = "observed"):
    status, body = await geofence.preview_async(country_code, scope=scope)
    return JSONResponse(status_code=status, content=body)


@app.post("/api/geofence")
async def geofence_block(req: geofence.GeofenceRequest):
    status, body = await geofence.block_async(req.country_code, req.confirm, scope=req.scope)
    return JSONResponse(status_code=status, content=body)


@app.post("/api/undo_geofence")
def geofence_undo(req: geofence.UndoRequest | None = None):
    # Body is optional: a bare POST (the U shortcut) undoes the most recent geofence.
    status, body = geofence.undo(req.country_code if req else None)
    return JSONResponse(status_code=status, content=body)


@app.get("/api/geofence/state")
def geofence_state():
    status, body = geofence.state()
    return JSONResponse(status_code=status, content=body)


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
