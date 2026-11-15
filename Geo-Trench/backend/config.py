"""Loads configuration from backend/.env with sane defaults."""
from pathlib import Path
import os

from dotenv import load_dotenv

BACKEND_DIR = Path(__file__).resolve().parent
load_dotenv(BACKEND_DIR / ".env")


def _bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(raw.strip())
    except ValueError:
        return default


def _float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return float(raw.strip())
    except ValueError:
        return default


def _path(name: str, default: str) -> Path:
    p = Path(os.getenv(name, default).strip())
    return p if p.is_absolute() else (BACKEND_DIR / p).resolve()


DEMO_MODE: bool = _bool("DEMO_MODE", True)
ENFORCE_FIREWALL: bool = _bool("ENFORCE_FIREWALL", False)
RULE_TTL_MINUTES: int = _int("RULE_TTL_MINUTES", 30)
MAXMIND_CITY_PATH: Path = _path("MAXMIND_CITY_PATH", "data/GeoLite2-City.mmdb")
MAXMIND_ASN_PATH: Path = _path("MAXMIND_ASN_PATH", "data/GeoLite2-ASN.mmdb")
ORIGIN_LAT: float = _float("ORIGIN_LAT", 43.0731)
ORIGIN_LNG: float = _float("ORIGIN_LNG", -89.4012)
DB_PATH: Path = _path("DB_PATH", "geotrench.db")
RETENTION_DAYS: int = _int("RETENTION_DAYS", 7)

# Protected processes: never quarantined or killed. Unknown exe paths are treated as protected.
PROTECTED_PATHS = (
    r"C:\Windows",
    r"C:\Program Files",
    r"C:\Program Files (x86)",
    r"C:\ProgramData\Microsoft",
)
PROTECTED_PIDS = frozenset({0, 4})
PROTECTED_NAMES = frozenset({
    "explorer.exe", "svchost.exe", "lsass.exe", "csrss.exe", "wininit.exe", "services.exe", "system",
})

ORIGIN_NAME: str =os.getenv("ORIGIN_NAME", "Madison, WI").strip() or "Madison, WI"
