"""In-memory operation event bus for live, visible actions. Thread-safe; nothing here raises.

- start_op / step / end_op describe one action (quarantine, restore, geofence, ...), using the REAL step
  boundaries of the existing code. emit_connections_changed tells the UI to refetch /api/connections.
- Events live in a bounded deque (500). Ids are a monotonically increasing integer, so clients can resume
  with Last-Event-ID. Op ids are deterministic per kind: "quarantine-1", "quarantine-2", ...
- Every event passes a final sanitize step: strings that look like Windows paths, contain the Windows
  username or this machine's hostname, or contain a private/loopback/link-local IP (or a known gateway/DNS
  address) are dropped (set to None) before the event is stored.
"""
import asyncio
import getpass
import ipaddress
import json
import logging
import os
import re
import socket
import threading
import time
from collections import OrderedDict, deque
from datetime import datetime, timezone

log = logging.getLogger("geotracker.events")

MAX_EVENTS = 500
MAX_OPS = 500
KINDS = ("quarantine", "restore", "delete_quarantine", "geofence", "undo_geofence", "stop_process", "sync")
STATUSES = ("running", "ok", "failed")
STREAM_POLL_SECONDS = 0.1
STREAM_PING_SECONDS = 15.0
STREAM_RETRY_MS = 2000

_lock = threading.Lock()
_events = deque(maxlen=MAX_EVENTS)
_next_id = 0
_op_counters = {}          # kind -> last number issued
_ops = OrderedDict()       # op_id -> {"kind", "target", "is_simulated", "started"}
_shutdown = threading.Event()


# ---------------------------------------------------------------- sanitize

_PATH_RE = re.compile(r"(?:[A-Za-z]:[\\/])|(?:\\\\[^\\\s]+\\)")
_IPV4_RE = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
_IPV6_RE = re.compile(r"(?<![0-9A-Fa-f:])([0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7})(?![0-9A-Fa-f:])")


def _sensitive_words():
    words = set()
    for value in (_safe_call(getpass.getuser), os.environ.get("USERNAME"),
                  os.path.basename((os.environ.get("USERPROFILE") or "").rstrip("\\/")),
                  _safe_call(socket.gethostname), os.environ.get("COMPUTERNAME")):
        if value and len(value) >= 3:
            words.add(value.casefold())
    return tuple(words)


def _safe_call(fn):
    try:
        return fn()
    except Exception:
        return None


_WORDS = _sensitive_words()


def _never_block_ips():
    """Gateway/DNS/never-block IPs already discovered by firewall.py (never triggers a lookup)."""
    try:
        import firewall
        cache = firewall._never_block_cache
        return set(cache[1]) if cache else set()
    except Exception:
        return set()


def _is_sensitive_ip(text, never_block):
    for m in _IPV4_RE.finditer(text):
        try:
            ip = ipaddress.ip_address(m.group(1))
        except ValueError:
            continue
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified or str(ip) in never_block:
            return True
    for m in _IPV6_RE.finditer(text):
        try:
            ip = ipaddress.ip_address(m.group(1))
        except ValueError:
            continue
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified or str(ip) in never_block:
            return True
    return False


def _bad_string(s, never_block):
    if _PATH_RE.search(s):
        return True
    low = s.casefold()
    if any(w in low for w in _WORDS):
        return True
    return _is_sensitive_ip(s, never_block)


def sanitize(value, _never_block=None):
    """Return a copy with every unsafe string replaced by None. Never raises."""
    try:
        nb = _never_block if _never_block is not None else _never_block_ips()
        if isinstance(value, str):
            return None if _bad_string(value, nb) else value
        if isinstance(value, dict):
            return {k: sanitize(v, nb) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [sanitize(v, nb) for v in value]
        if value is None or isinstance(value, (bool, int, float)):
            return value
        return sanitize(str(value), nb)
    except Exception:
        return None


# ---------------------------------------------------------------- core

def _now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _target(target):
    t = target or {}
    return {k: t.get(k) for k in ("conn_id", "country_code", "manifest_id") if t.get(k) is not None}


def _append(event):
    """Assign the id, sanitize, store. Returns the stored event (or None)."""
    global _next_id
    try:
        clean = sanitize(event)
        with _lock:
            _next_id += 1
            clean["id"] = _next_id
            _events.append(clean)
        return clean
    except Exception:
        log.exception("event append failed")
        return None


def start_op(kind, target=None, is_simulated=False):
    """Begin an operation. Returns a deterministic op id like 'quarantine-7' (None on error)."""
    try:
        kind = kind if kind in KINDS else "sync"
        with _lock:
            n = _op_counters.get(kind, 0) + 1
            _op_counters[kind] = n
            op_id = f"{kind}-{n}"
            _ops[op_id] = {"kind": kind, "target": _target(target), "is_simulated": bool(is_simulated),
                           "started": time.monotonic()}
            while len(_ops) > MAX_OPS:
                _ops.popitem(last=False)
        _append(_event("op_start", op_id, None, f"{kind} started", "running", None))
        return op_id
    except Exception:
        log.exception("start_op failed")
        return None


def _event(etype, op_id, step_name, message, status, data, is_simulated=None):
    with _lock:
        meta = _ops.get(op_id) or {}
        if is_simulated is not None and op_id in _ops:
            meta["is_simulated"] = bool(is_simulated)
        elapsed = None if not meta else round((time.monotonic() - meta["started"]) * 1000, 1)
        return {
            "ts": _now_iso(), "type": etype, "op_id": op_id, "kind": meta.get("kind"),
            "target": dict(meta.get("target") or {}), "is_simulated": bool(meta.get("is_simulated")),
            "step": step_name, "message": message, "status": status, "elapsed_ms": elapsed,
            "data": dict(data) if isinstance(data, dict) else None,
        }


def step(op_id, step_name, message, status="running", data=None, is_simulated=None):
    if not op_id:
        return None
    status = status if status in STATUSES else "running"
    return _append(_event("op_step", op_id, step_name, message, status, data, is_simulated))


def end_op(op_id, ok, message, data=None, is_simulated=None):
    if not op_id:
        return None
    return _append(_event("op_end", op_id, "done" if ok else "failed", message,
                          "ok" if ok else "failed", data, is_simulated))


def emit_connections_changed(reason):
    return _append({"ts": _now_iso(), "type": "connections_changed", "op_id": None, "kind": None,
                    "target": {}, "is_simulated": False, "step": None, "message": str(reason),
                    "status": None, "elapsed_ms": None, "data": None})


# ---------------------------------------------------------------- reads

def recent(limit=50):
    """Newest-last list of up to `limit` (1..500) events."""
    try:
        limit = max(1, min(MAX_EVENTS, int(limit)))
    except (TypeError, ValueError):
        limit = 50
    with _lock:
        return [dict(e) for e in list(_events)[-limit:]]


def since(last_id):
    """Events with id > last_id, oldest first (everything buffered if last_id predates the buffer)."""
    with _lock:
        return [dict(e) for e in _events if e["id"] > last_id]


def newest_id():
    with _lock:
        return _events[-1]["id"] if _events else 0


def op_events(op_id):
    with _lock:
        return [dict(e) for e in _events if e.get("op_id") == op_id]


# ---------------------------------------------------------------- streaming

def shutdown():
    """Called FIRST in lifespan shutdown so open streams end and run.py --stop never hangs."""
    _shutdown.set()


def is_shutting_down():
    return _shutdown.is_set()


def parse_last_id(header_value, query_value):
    for v in (header_value, query_value):
        try:
            if v is not None and str(v).strip() != "":
                return max(0, int(str(v).strip()))
        except ValueError:
            continue
    return None


def frame(event):
    return f"id: {event['id']}\nevent: {event['type']}\ndata: {json.dumps(event, separators=(',', ':'))}\n\n"


async def sse_stream(is_disconnected, last_id=None, poll_seconds=STREAM_POLL_SECONDS,
                     ping_seconds=STREAM_PING_SECONDS, clock=time.monotonic):
    """Async generator of SSE text. Resumes after last_id (else starts after the newest event).
    Exits when the client disconnects or shutdown() was called."""
    cursor = newest_id() if last_id is None else last_id
    yield f"retry: {STREAM_RETRY_MS}\n\n"
    last_ping = clock()
    while not _shutdown.is_set():
        try:
            if await is_disconnected():
                break
        except Exception:
            break
        batch = since(cursor)
        for event in batch:
            cursor = event["id"]
            yield frame(event)
        if clock() - last_ping >= ping_seconds:
            last_ping = clock()
            yield ": ping\n\n"
        await asyncio.sleep(poll_seconds)


def _reset_for_tests():
    global _next_id
    with _lock:
        _events.clear()
        _ops.clear()
        _op_counters.clear()
        _next_id = 0
    _shutdown.clear()
