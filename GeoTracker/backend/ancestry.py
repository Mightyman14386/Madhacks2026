"""Process ancestry engine: who launched this process, and who launched that one.

Every psutil call is individually guarded and degrades to None/"unknown".
Nothing in this module raises to callers.
"""
import copy
import getpass
import os
import re
import threading
import time

import psutil

MAX_DEPTH = 12
CACHE_TTL_SECONDS = 10.0

_PSUTIL_ERRORS = (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess)

_cache = {}  # (pid, create_time) -> (stored_at, result)
_cache_lock = threading.Lock()


# ---------------------------------------------------------------- redaction

def _known_usernames():
    names = set()
    try:
        names.add(getpass.getuser())
    except Exception:
        pass
    try:
        profile = os.environ.get("USERPROFILE")
        if profile:
            names.add(os.path.basename(profile.rstrip("\\/")))
    except Exception:
        pass
    return {n for n in names if n}


# Current user first (handles names with spaces), then any other C:\Users\<name>.
_KNOWN_USER_PATTERNS = [
    re.compile(r"([a-z]:[\\/]users[\\/])" + re.escape(n) + r"(?=[\\/\"]|\s|$)", re.IGNORECASE)
    for n in sorted(_known_usernames(), key=len, reverse=True)
]
_GENERIC_USER_PATTERN = re.compile(r"([a-z]:[\\/]users[\\/])(?!<user>)[^\\/\"\s]+", re.IGNORECASE)


def redact(text):
    """Replace the Windows username in any C:\\Users\\<name> path with <user>."""
    if not text:
        return text
    try:
        for pattern in _KNOWN_USER_PATTERNS:
            text = pattern.sub(r"\1<user>", text)
        return _GENERIC_USER_PATTERN.sub(r"\1<user>", text)
    except Exception:
        return None  # if redaction fails, drop the value rather than leak it


# ---------------------------------------------------------------- psutil guards

def _safe_name(proc):
    try:
        return proc.name() or "unknown"
    except _PSUTIL_ERRORS:
        return "unknown"
    except Exception:
        return "unknown"


def _safe_exe(proc):
    try:
        return proc.exe() or None
    except _PSUTIL_ERRORS:
        return None
    except Exception:
        return None


def _safe_cmdline(proc):
    try:
        parts = proc.cmdline()
        return " ".join(parts) if parts else None
    except _PSUTIL_ERRORS:
        return None
    except Exception:
        return None


def _safe_parent(proc):
    try:
        return proc.parent()
    except _PSUTIL_ERRORS:
        return None
    except Exception:
        return None


def _safe_create_time(proc):
    try:
        return proc.create_time()
    except _PSUTIL_ERRORS:
        return None
    except Exception:
        return None


# ---------------------------------------------------------------- core

def _unknown_result(pid):
    return {
        "pid": pid,
        "name": "unknown",
        "exe": None,
        "raw_exe": None,
        "cmdline_redacted": None,
        "ancestry": ["unknown"],
        "ancestry_detail": [{"pid": pid, "name": "unknown", "exe": None}],
    }


def _build(proc):
    raw_exe = _safe_exe(proc)
    name = _safe_name(proc)

    chain = [{"pid": proc.pid, "name": name, "exe": redact(raw_exe)}]
    seen = {proc.pid}
    current = proc
    child_ct = _safe_create_time(proc)

    while len(chain) < MAX_DEPTH:
        parent = _safe_parent(current)
        if parent is None or parent.pid in seen:
            break
        parent_ct = _safe_create_time(parent)
        # PID reuse: a "parent" born after its child is an unrelated process.
        if child_ct is not None and parent_ct is not None and parent_ct > child_ct:
            break
        seen.add(parent.pid)
        chain.append({"pid": parent.pid, "name": _safe_name(parent), "exe": redact(_safe_exe(parent))})
        current = parent
        child_ct = parent_ct

    chain.reverse()  # root -> leaf
    return {
        "pid": proc.pid,
        "name": name,
        "exe": redact(raw_exe),
        # raw_exe is the UNREDACTED path, for server-side use only (protected-path
        # checks, quarantine). It must NEVER be returned by an API endpoint or sent
        # to an LLM. Use public_view() before returning a result to anyone.
        "raw_exe": raw_exe,
        "cmdline_redacted": redact(_safe_cmdline(proc)),
        "ancestry": [p["name"] for p in chain],
        "ancestry_detail": chain,
    }


def get_process_info(pid):
    """Return process info with ancestry (root -> leaf). Never raises."""
    try:
        try:
            proc = psutil.Process(pid)
        except _PSUTIL_ERRORS:
            return _unknown_result(pid)

        key = (pid, _safe_create_time(proc))
        now = time.monotonic()
        with _cache_lock:
            hit = _cache.get(key)
            if hit is not None and now - hit[0] < CACHE_TTL_SECONDS:
                return copy.deepcopy(hit[1])

        result = _build(proc)

        with _cache_lock:
            for k in [k for k, (t, _) in _cache.items() if now - t >= CACHE_TTL_SECONDS]:
                del _cache[k]
            _cache[key] = (now, result)
        return copy.deepcopy(result)
    except Exception:
        return _unknown_result(pid)


def public_view(info):
    """Strip server-only fields (raw_exe) before returning to a client or an LLM."""
    return {k: v for k, v in info.items() if k != "raw_exe"}


if __name__ == "__main__":
    import json

    for label, pid in (("Current process", os.getpid()), ("Parent process", os.getppid())):
        info = get_process_info(pid)
        print(f"\n== {label} (pid {pid}) ==")
        print("  " + " -> ".join(info["ancestry"]))
        print(json.dumps(public_view(info), indent=2))
