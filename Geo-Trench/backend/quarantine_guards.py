"""Pure guard functions for quarantine decisions. Single source of truth for "is this protected?".

No side effects: nothing here touches processes or moves files.
Every check fails closed: when in doubt, the target is treated as protected.
"""
import ntpath
import os
import re

import ancestry
import config

QUARANTINE_DIR = r"C:\GeoTrench\quarantine"

_MULTI_SLASH = re.compile(r"(?<!^)\\{2,}")


def _strip_components(path):
    """Windows ignores trailing dots and spaces in each path component; so do we."""
    parts = path.split("\\")
    out = []
    for i, part in enumerate(parts):
        if part in (".", "..") or (i == 0 and part.endswith(":")):
            out.append(part)
            continue
        stripped = part.rstrip(". ")
        if stripped or i == 0:
            out.append(stripped)
    return "\\".join(out)


def normalize_path(p):
    """Canonical, comparable form of a Windows path, or None for None/empty/unusable input."""
    if p is None:
        return None
    try:
        s = str(p).strip()
        if not s:
            return None
        s = s.replace("/", "\\")
        s = _MULTI_SLASH.sub(r"\\", s)
        s = _strip_components(s)
        try:
            s = os.path.realpath(s)
        except Exception:
            pass
        if s.startswith("\\\\?\\"):
            s = s[4:]
        s = ntpath.normpath(s)
        s = _strip_components(s)
        return ntpath.normcase(s).casefold()
    except Exception:
        return None


def _protected_roots():
    roots = []
    for p in config.PROTECTED_PATHS:
        n = normalize_path(p)
        if n:
            roots.append(n.rstrip("\\"))
    return tuple(roots)


_PROTECTED_ROOTS = _protected_roots()


def is_under_protected(path):
    """True if path is inside (or equal to) any protected root. Fails closed on None/unusable input."""
    n = normalize_path(path)
    if n is None:
        return True
    for root in _PROTECTED_ROOTS:
        if n == root or n.startswith(root + "\\"):
            return True
    return False


def is_protected_target(raw_exe, pid, name):
    """True if this process/file must never be quarantined or stopped. Fails closed."""
    try:
        if pid in config.PROTECTED_PIDS or pid == os.getpid():
            return True
        if name and str(name).strip().casefold() in config.PROTECTED_NAMES:
            return True
        if not raw_exe:
            return True
        return is_under_protected(raw_exe)
    except Exception:
        return True


def redact_user_path(p):
    """Replace the Windows username in a path with <user>."""
    return ancestry.redact(p)


# Startup assertion (explicit, so it survives python -O).
if is_under_protected(QUARANTINE_DIR):
    raise RuntimeError(f"QUARANTINE_DIR must not be under a protected path: {QUARANTINE_DIR}")
