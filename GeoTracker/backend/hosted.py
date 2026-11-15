"""Read-only hosted API. Never imports the local process-control server."""
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
import incidents

DIST = Path(__file__).resolve().parent.parent / "frontend" / "dist"

@asynccontextmanager
async def lifespan(app):
    yield
    incidents.incident_feed.close()

app = FastAPI(title="GeoTracker", lifespan=lifespan)

@app.get("/api/health")
def health():
    return {"status": "ok", "deployment": "hosted", "is_admin": False,
            "demo_mode": False, "enforcement_enabled": False,
            "geoip_loaded": False, "geoip_fallback": False}

@app.get("/api/incidents")
def get_incidents():
    snapshot = incidents.incident_feed.snapshot()
    status = 503 if snapshot["state"] == "error" and not snapshot["fetched_at"] else 200
    return JSONResponse(status_code=status, content=snapshot)

@app.get("/api/capabilities")
def capabilities():
    return {"deployment": "hosted", "is_admin": False, "firewall_mode": "unavailable",
            "features": {key: False for key in
                         ("quarantine", "restore", "geofence", "stop_process", "events_stream")}}

@app.get("/api/connections")
def connections():
    return {"connections": [], "anycast": [], "origin": None, "stats": {},
            "warnings": ["Hosted mode cannot observe your device. Use Explore demo to learn, or run the Windows backend locally."],
            "truncated": False}

@app.get("/api/audit")
def audit():
    return []

@app.get("/api/quarantine/list")
def quarantine():
    return {"ok": True, "items": []}

@app.get("/api/events/stream", status_code=204)
def events():
    # HTTP 204 tells EventSource to stop reconnecting.
    return None

@app.api_route("/api/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
def unavailable(path: str):
    return JSONResponse(status_code=404, content={
        "message": "This feature requires the local Windows backend and is unavailable in hosted mode."})

# Registered after API routes so missing API endpoints cannot return the frontend.
app.mount("/", StaticFiles(directory=DIST, html=True), name="frontend")
