"""Builds and caches per-country IPv4/IPv6 CIDR blocks from the local MaxMind City database.

- Iterates the MaxMind City mmdb directly via maxminddb (a dependency of geoip2).
- Drops any network overlapping private, reserved, loopback, link-local, multicast, or unspecified space.
- Excludes every firewall.get_never_block() address using ipaddress.address_exclude so gateways,
  DNS servers, and never-block hosts are never covered by a country rule.
- Collapses and deterministically sorts v4 and v6 networks separately.
- Caches results to backend/data/ranges_<CC>.json keyed by the mmdb file's size and mtime_ns.
"""
import ipaddress
import json
import logging
import sys
import time
from pathlib import Path

import config
import firewall

log = logging.getLogger("geotrench.geo_ranges")

CACHE_DIR: Path = config.BACKEND_DIR / "data"

# Non-routable / special-purpose ranges that must never be included in a country block,
# even if a coarse supernet in an mmdb overlaps them.
_NON_PUBLIC_V4 = tuple(ipaddress.ip_network(c) for c in (
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "255.255.255.255/32",
))

_NON_PUBLIC_V6 = tuple(ipaddress.ip_network(c) for c in (
    "::/128",
    "::1/128",
    "::ffff:0:0/96",
    "64:ff9b:1::/48",
    "100::/64",
    "2001::/23",
    "2001:db8::/32",
    "2002::/16",
    "3fff::/20",
    "fc00::/7",
    "fe80::/10",
    "fec0::/10",
    "ff00::/8",
))


class GeoRangesUnavailableError(RuntimeError):
    """Raised when the MaxMind City mmdb is missing and country scope is unavailable."""


def _is_public_network(net) -> bool:
    """True only if `net` is strictly global and does not overlap any private/reserved/special range."""
    if getattr(net, "ipv4_mapped", None) is not None:
        return False
    if (net.is_private or net.is_loopback or net.is_link_local
            or net.is_multicast or net.is_reserved or net.is_unspecified
            or not net.is_global):
        return False
    bad_list = _NON_PUBLIC_V4 if net.version == 4 else _NON_PUBLIC_V6
    for bad in bad_list:
        if net.overlaps(bad):
            return False
    return True


def _exclude_addresses(networks, exclude_ips):
    """Subtract each IP in `exclude_ips` (same IP version) from `networks` using address_exclude."""
    if not exclude_ips:
        return list(networks)
    current = list(networks)
    for ip in exclude_ips:
        ip_net = ipaddress.ip_network(ip)
        next_nets = []
        for net in current:
            if net.overlaps(ip_net):
                next_nets.extend(net.address_exclude(ip_net))
            else:
                next_nets.append(net)
        current = next_nets
    return current


def _never_block_by_version(never_block_ips=None):
    raw = firewall.get_never_block() if never_block_ips is None else never_block_ips
    v4, v6 = [], []
    for item in raw or ():
        try:
            ip = ipaddress.ip_address(str(item).strip())
        except ValueError:
            continue
        if getattr(ip, "ipv4_mapped", None) is not None:
            ip = ip.ipv4_mapped
        if ip.version == 4:
            v4.append(ip)
        else:
            v6.append(ip)
    v4.sort(key=int)
    v6.sort(key=int)
    return v4, v6


def clean_and_collapse(raw_networks, never_block_ips=None):
    """Filter, collapse, subtract never-block hosts, and deterministically sort CIDRs.

    Accepts iterable of IPv4Network/IPv6Network or CIDR strings.
    Returns (v4_cidrs: list[str], v6_cidrs: list[str]).
    """
    v4_raw, v6_raw = [], []
    for item in raw_networks or ():
        try:
            net = item if isinstance(item, (ipaddress.IPv4Network, ipaddress.IPv6Network)) \
                else ipaddress.ip_network(str(item).strip(), strict=False)
        except ValueError:
            continue
        if getattr(net.network_address, "ipv4_mapped", None) is not None:
            continue
        if not _is_public_network(net):
            continue
        if net.version == 4:
            v4_raw.append(net)
        else:
            v6_raw.append(net)

    v4_collapsed = list(ipaddress.collapse_addresses(v4_raw))
    v6_collapsed = list(ipaddress.collapse_addresses(v6_raw))

    nb_v4, nb_v6 = _never_block_by_version(never_block_ips)
    v4_clean = [n for n in _exclude_addresses(v4_collapsed, nb_v4) if _is_public_network(n)]
    v6_clean = [n for n in _exclude_addresses(v6_collapsed, nb_v6) if _is_public_network(n)]

    v4_final = sorted(ipaddress.collapse_addresses(v4_clean),
                      key=lambda n: (int(n.network_address), n.prefixlen))
    v6_final = sorted(ipaddress.collapse_addresses(v6_clean),
                      key=lambda n: (int(n.network_address), n.prefixlen))
    return [str(n) for n in v4_final], [str(n) for n in v6_final]


def _iso_code_of(record) -> str | None:
    if not isinstance(record, dict):
        return None
    country = record.get("country")
    if isinstance(country, dict):
        code = country.get("iso_code")
        if code:
            return str(code).upper()
    reg = record.get("registered_country")
    if isinstance(reg, dict):
        code = reg.get("iso_code")
        if code:
            return str(code).upper()
    return None


def _iter_mmdb_country(mmdb_path: Path, code: str):
    import maxminddb
    with maxminddb.open_database(str(mmdb_path)) as reader:
        for network, record in reader:
            if _iso_code_of(record) == code:
                yield network


def _cache_path(code: str, cache_dir: Path | None = None) -> Path:
    base = CACHE_DIR if cache_dir is None else Path(cache_dir)
    return base / f"ranges_{code}.json"


def _mmdb_stat(mmdb_path: Path | None = None):
    path = config.MAXMIND_CITY_PATH if mmdb_path is None else Path(mmdb_path)
    if not path.is_file():
        raise GeoRangesUnavailableError(
            "Country-wide geofence is unavailable because the MaxMind GeoLite2-City database is missing."
        )
    st = path.stat()
    return path, st.st_size, st.st_mtime_ns, round(st.st_mtime, 3)


def is_cached(cc: str, mmdb_path: Path | None = None, cache_dir: Path | None = None) -> bool:
    """True if a valid up-to-date cache file exists on disk for `cc`."""
    code = firewall.validate_cc(cc)
    if code is None:
        return False
    try:
        _, size, mtime_ns, mtime = _mmdb_stat(mmdb_path)
        cpath = _cache_path(code, cache_dir)
        if not cpath.is_file():
            return False
        data = json.loads(cpath.read_text(encoding="utf-8"))
        return (data.get("source_size") == size
                and (data.get("source_mtime_ns") == mtime_ns or data.get("source_mtime") == mtime)
                and isinstance(data.get("v4"), list)
                and isinstance(data.get("v6"), list))
    except Exception:
        return False


def country_ranges(cc: str, *, mmdb_path: Path | None = None, cache_dir: Path | None = None,
                   never_block_ips=None, raw_networks=None) -> dict:
    """Return {"v4": [...], "v6": [...], "built_ms": float, "source_mtime": float} for `cc`.

    Uses the on-disk cache keyed by mmdb size + mtime when available, and subtracts current
    never-block addresses so dynamic gateway/DNS changes are always respected.
    """
    code = firewall.validate_cc(cc)
    if code is None:
        raise ValueError("Invalid country code.")

    # Synthetic injection hook for unit tests without touching the real mmdb.
    if raw_networks is not None:
        started = time.perf_counter()
        v4, v6 = clean_and_collapse(raw_networks, never_block_ips=never_block_ips)
        built_ms = round((time.perf_counter() - started) * 1000, 1)
        return {"v4": v4, "v6": v6, "built_ms": built_ms, "source_mtime": 0.0}

    path, size, mtime_ns, mtime = _mmdb_stat(mmdb_path)
    cpath = _cache_path(code, cache_dir)

    cached_v4 = cached_v6 = None
    built_ms = 0.0
    if cpath.is_file():
        try:
            data = json.loads(cpath.read_text(encoding="utf-8"))
            if (data.get("source_size") == size
                    and (data.get("source_mtime_ns") == mtime_ns or data.get("source_mtime") == mtime)
                    and isinstance(data.get("v4"), list)
                    and isinstance(data.get("v6"), list)):
                cached_v4 = data["v4"]
                cached_v6 = data["v6"]
                built_ms = float(data.get("built_ms") or 0.0)
        except Exception as e:
            log.warning("Could not read range cache %s: %s", cpath, e)

    if cached_v4 is None or cached_v6 is None:
        started = time.perf_counter()
        v4_base, v6_base = clean_and_collapse(_iter_mmdb_country(path, code), never_block_ips=())
        built_ms = round((time.perf_counter() - started) * 1000, 1)
        try:
            cpath.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "country_code": code,
                "source_size": size,
                "source_mtime": mtime,
                "source_mtime_ns": mtime_ns,
                "built_ms": built_ms,
                "v4": v4_base,
                "v6": v6_base,
            }
            cpath.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        except Exception as e:
            log.warning("Could not write range cache %s: %s", cpath, e)
        cached_v4, cached_v6 = v4_base, v6_base

    # Always subtract live never-block addresses (gateways/DNS/configured hosts).
    nb_v4, nb_v6 = _never_block_by_version(never_block_ips)
    if nb_v4:
        v4_nets = [ipaddress.ip_network(c) for c in cached_v4]
        v4_nets = [n for n in _exclude_addresses(v4_nets, nb_v4) if _is_public_network(n)]
        v4_nets = sorted(ipaddress.collapse_addresses(v4_nets),
                         key=lambda n: (int(n.network_address), n.prefixlen))
        cached_v4 = [str(n) for n in v4_nets]
    if nb_v6:
        v6_nets = [ipaddress.ip_network(c) for c in cached_v6]
        v6_nets = [n for n in _exclude_addresses(v6_nets, nb_v6) if _is_public_network(n)]
        v6_nets = sorted(ipaddress.collapse_addresses(v6_nets),
                         key=lambda n: (int(n.network_address), n.prefixlen))
        cached_v6 = [str(n) for n in v6_nets]

    return {
        "v4": list(cached_v4),
        "v6": list(cached_v6),
        "built_ms": built_ms,
        "source_mtime": mtime,
    }


def ipv4_address_count(v4_cidrs) -> int:
    """Total number of IPv4 addresses across `v4_cidrs`."""
    return sum(ipaddress.ip_network(c, strict=True).num_addresses for c in (v4_cidrs or ()))


def main(argv=None) -> int:
    codes = list(argv if argv is not None else sys.argv[1:])
    if not codes:
        print("Usage: python geo_ranges.py <CC> [<CC> ...]", file=sys.stderr)
        return 1
    rc = 0
    for raw in codes:
        code = firewall.validate_cc(raw)
        if code is None:
            print(f"{raw}: invalid country code", file=sys.stderr)
            rc = 1
            continue
        try:
            started = time.perf_counter()
            res = country_ranges(code)
            elapsed_ms = round((time.perf_counter() - started) * 1000, 1)
            total_v4 = ipv4_address_count(res["v4"])
            print(
                f"{code}: v4_ranges={len(res['v4'])}  v6_ranges={len(res['v6'])}  "
                f"ipv4_addresses={total_v4:,}  built_ms={res['built_ms']} (total {elapsed_ms} ms)"
            )
        except Exception as e:
            print(f"{code}: ERROR - {e}", file=sys.stderr)
            rc = 1
    return rc


if __name__ == "__main__":
    raise SystemExit(main())