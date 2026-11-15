"""Windows Firewall core for Geo-Trench geofencing. No endpoints here.

Safety model:
- Only outbound Block rules named GeoTrench-<CC> in group GeoTrench are ever created, changed, or removed.
- Nothing runs unless ENFORCE_FIREWALL is true AND the server is elevated; otherwise every action is a dry run.
- Only validated values (a 2-letter country code and canonical IP strings) are ever placed into a
  PowerShell script. The command builders re-validate and raise ValueError: last line of defense.
- Gateways, DNS servers and never-block hosts are filtered out so a rule can't cut off the network.
"""
import ctypes
import ipaddress
import json
import logging
import os
import re
import socket
import struct
import subprocess
import threading
import time
import uuid
from pathlib import Path
from urllib.parse import urlparse

import config

log = logging.getLogger("geotrench.firewall")

NEVER_BLOCK_TTL_SECONDS = 300
PS_TIMEOUT_SECONDS = 15
DISPLAY_MAX_IPS = 10
DISPLAY_MAX_RANGES = 5
PS_INLINE_MAX_CHARS = 8000
PS_TMP_DIR = Path(r"C:\GeoTrench\tmp")
RULE_DESCRIPTION = "Geo-Trench geofence (auto-expires)"

_CC_RE = re.compile(r"^[A-Z]{2}$")
_RULE_CC_RE = re.compile(r"^([A-Z]{2})(?:-\d{2,})?$")
_SAFE_IP_CHARS = re.compile(r"^[0-9A-Fa-f.:]+$")  # canonical IPs only: no scope ids, quotes, spaces, commas
_SAFE_CIDR_CHARS = re.compile(r"^[0-9A-Fa-f.:/]+$")
_CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)

_lock = threading.Lock()                # serializes rule-changing operations
_never_block_lock = threading.Lock()
_never_block_cache = None               # (fetched_monotonic, frozenset of ips, warnings list)


# ---------------------------------------------------------------- admin / mode

def is_admin():
    """True only on Windows when elevated. Never raises."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def enforcement_mode():
    if not config.ENFORCE_FIREWALL:
        return {"mode": "dry_run", "reason": "ENFORCE_FIREWALL is false"}
    if not is_admin():
        return {"mode": "dry_run", "reason": "Not running as administrator"}
    return {"mode": "enforced", "reason": "ENFORCE_FIREWALL is true and running as administrator"}


def _enforced():
    return enforcement_mode()["mode"] == "enforced"


# ---------------------------------------------------------------- PowerShell runner

def _invoke_ps_args(args, timeout):
    return subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", *args],
        capture_output=True, text=True, timeout=timeout, creationflags=_CREATE_NO_WINDOW,
    )


def _run_ps(script, timeout=PS_TIMEOUT_SECONDS):
    """Run a PowerShell script. Returns (ok, stdout, stderr). Never raises.

    Windows caps command lines near 32k chars, so if `script` is over 8000 chars, writes it to a
    temp .ps1 in C:\\GeoTrench\\tmp, runs it with -File, and deletes the file in finally.
    Callers must only interpolate values that passed validate_cc / _canonical_ip.
    """
    tmp_path = None
    try:
        if len(script or "") > PS_INLINE_MAX_CHARS:
            PS_TMP_DIR.mkdir(parents=True, exist_ok=True)
            tmp_path = PS_TMP_DIR / f"geotrench_{uuid.uuid4().hex}.ps1"
            tmp_path.write_text(script, encoding="utf-8")
            proc = _invoke_ps_args(["-File", str(tmp_path)], timeout=timeout)
        else:
            proc = _invoke_ps_args(["-Command", script], timeout=timeout)
    except subprocess.TimeoutExpired:
        log.warning("PowerShell timed out after %ss", timeout)
        return False, "", "timeout"
    except OSError as e:
        log.warning("PowerShell could not start: %s", e)
        return False, "", str(e)
    finally:
        if tmp_path is not None:
            try:
                os.remove(tmp_path)
            except OSError:
                pass
    ok = proc.returncode == 0
    if not ok:
        log.warning("PowerShell failed (exit %s): %s", proc.returncode, (proc.stderr or "").strip()[:300])
    return ok, proc.stdout or "", proc.stderr or ""


# ---------------------------------------------------------------- never-block list

# Query each prefix separately and exit 0: on machines with no IPv6 default route, a combined
# query "fails" (exit 1) even though the IPv4 gateway was found.
_GATEWAY_SCRIPT = (
    "foreach ($p in '0.0.0.0/0','::/0') { Get-NetRoute -DestinationPrefix $p -ErrorAction SilentlyContinue "
    "| Select-Object -ExpandProperty NextHop }; exit 0"
)
_DNS_SCRIPT = (
    "Get-DnsClientServerAddress -ErrorAction SilentlyContinue "
    "| Select-Object -ExpandProperty ServerAddresses; exit 0"
)


def _parse_ip_lines(text):
    out = set()
    for line in (text or "").splitlines():
        ip = _canonical_ip(line)
        if ip is not None and ip not in ("0.0.0.0", "::"):
            out.add(ip)
    return out


def _host_of(value):
    v = value.strip()
    if "://" in v:
        v = urlparse(v).hostname or ""
    return v.split("/")[0].strip()


def _resolve(host):
    ips = set()
    for info in socket.getaddrinfo(host, None):
        ip = _canonical_ip(info[4][0])
        if ip is not None:
            ips.add(ip)
    return ips


def _build_never_block():
    ips, warnings = set(), []
    for label, script in (("default gateway", _GATEWAY_SCRIPT), ("DNS servers", _DNS_SCRIPT)):
        ok, out, _ = _run_ps(script)
        if ok:
            found = _parse_ip_lines(out)
            ips |= found
            if not found:
                warnings.append(f"No {label} found.")
        else:
            warnings.append(f"Could not read {label}.")

    hosts = list(config.NEVER_BLOCK_HOSTS)
    if config.DATABRICKS_HOST:
        hosts.append(config.DATABRICKS_HOST)
    for raw in hosts:
        host = _host_of(raw)
        if not host:
            continue
        try:
            ips |= _resolve(host)
        except Exception:
            warnings.append(f"Could not resolve never-block host {host}.")
    return frozenset(ips), warnings


def get_never_block():
    """IPs that must never be blocked (gateways, DNS, never-block hosts). Cached for 5 minutes."""
    global _never_block_cache
    with _never_block_lock:
        now = time.monotonic()
        if _never_block_cache is None or now - _never_block_cache[0] >= NEVER_BLOCK_TTL_SECONDS:
            ips, warnings = _build_never_block()
            _never_block_cache = (now, ips, warnings)
        return set(_never_block_cache[1])


def never_block_warnings():
    with _never_block_lock:
        return list(_never_block_cache[2]) if _never_block_cache else []


# ---------------------------------------------------------------- validation

def _canonical_ip(value):
    """Canonical string for a plain IP address, or None. Rejects scope ids and anything odd."""
    try:
        ip = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None
    if getattr(ip, "scope_id", None):
        return None
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    s = str(ip)
    return s if _SAFE_IP_CHARS.match(s) else None


def _sort_key(ip_str):
    ip = ipaddress.ip_address(ip_str)
    return (ip.version, int(ip))


def filter_ips(ips):
    """Returns (allowed sorted list, skipped [{ip, reason}]). Never raises on bad input."""
    never = {_canonical_ip(x) for x in get_never_block()} - {None}
    allowed, skipped, seen = set(), [], set()
    for raw in ips or []:
        canon = _canonical_ip(raw)
        if canon is None:
            skipped.append({"ip": str(raw), "reason": "invalid"})
            continue
        if canon in seen:
            continue  # dedupe
        seen.add(canon)
        ip = ipaddress.ip_address(canon)
        if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
                or ip.is_reserved or ip.is_unspecified or not ip.is_global):
            skipped.append({"ip": canon, "reason": "private/reserved range"})
            continue
        if canon in never:
            skipped.append({"ip": canon, "reason": "gateway/DNS/never-block host"})
            continue
        allowed.add(canon)

    ordered = sorted(allowed, key=_sort_key)
    cap = max(0, int(config.MAX_IPS_PER_RULE))
    for ip in ordered[cap:]:
        skipped.append({"ip": ip, "reason": "rule size cap"})
    return ordered[:cap], skipped


def validate_cc(cc):
    """Uppercase ISO 3166 alpha-2 code, or None."""
    if cc is None:
        return None
    s = str(cc).strip().upper()
    return s if _CC_RE.match(s) else None


def rule_name(cc):
    code = validate_cc(cc)
    if code is None:
        raise ValueError("invalid country code")
    return config.FIREWALL_RULE_PREFIX + code


def chunk_rule_name(cc, index):
    code = validate_cc(cc)
    if code is None:
        raise ValueError("invalid country code")
    idx = int(index)
    if idx < 1:
        raise ValueError("chunk index must be >= 1")
    return f"{config.FIREWALL_RULE_PREFIX}{code}-{idx:02d}"


def parse_rule_cc(name):
    """Map 'GeoTrench-DE' or 'GeoTrench-DE-01' back to 'DE', else None."""
    if not isinstance(name, str) or not name.startswith(config.FIREWALL_RULE_PREFIX):
        return None
    suffix = name[len(config.FIREWALL_RULE_PREFIX):]
    m = _RULE_CC_RE.match(suffix)
    return m.group(1) if m else None


def _checked_cidrs(cidrs):
    """Validate each CIDR with ipaddress.ip_network(strict=True) and sort deterministically."""
    nets = []
    for raw in cidrs or ():
        s = str(raw).strip()
        if not s or not _SAFE_CIDR_CHARS.match(s):
            raise ValueError(f"invalid CIDR: {raw!r}")
        net = ipaddress.ip_network(s, strict=True)
        if getattr(net.network_address, "ipv4_mapped", None) is not None:
            raise ValueError(f"ipv4-mapped CIDR not allowed: {raw!r}")
        canon = str(net)
        if canon != s or not _SAFE_CIDR_CHARS.match(canon):
            raise ValueError(f"non-canonical CIDR: {raw!r}")
        nets.append(net)
    if not nets:
        raise ValueError("apply_ranges requires at least one CIDR")
    nets.sort(key=lambda n: (n.version, int(n.network_address), n.prefixlen))
    return [str(n) for n in nets]


def chunk_cidrs(cc, cidrs, chunk_size=None):
    """Return [(rule_name, [cidr, ...]), ...] in deterministic sorted order."""
    ordered = _checked_cidrs(cidrs)
    size = max(1, int(config.FIREWALL_CHUNK_SIZE if chunk_size is None else chunk_size))
    chunks = []
    for i in range(0, len(ordered), size):
        idx = (i // size) + 1
        chunks.append((chunk_rule_name(cc, idx), ordered[i:i + size]))
    return chunks


# ---------------------------------------------------------------- command builders (pure)

def _checked_ips(ips):
    """Re-validate every IP; raise ValueError on anything that isn't a canonical address."""
    out = []
    for raw in ips or []:
        canon = _canonical_ip(raw)
        if canon is None or canon != str(raw).strip():
            raise ValueError("invalid IP address in rule")
        out.append(canon)
    if not out:
        raise ValueError("a rule needs at least one IP address")
    return out


def _ps_array(ips):
    return "@(" + ",".join(f"'{ip}'" for ip in ips) + ")"


def build_create(cc, ips):
    name = rule_name(cc)
    addrs = _ps_array(_checked_ips(ips))
    return (
        f"New-NetFirewallRule -Name '{name}' -DisplayName '{name}' -Group '{config.FIREWALL_RULE_GROUP}' "
        f"-Direction Outbound -Action Block -Profile Any -Enabled True -RemoteAddress {addrs} "
        f"-Description '{RULE_DESCRIPTION}' | Out-Null"
    )


def build_update(cc, ips):
    name = rule_name(cc)
    addrs = _ps_array(_checked_ips(ips))
    return f"Set-NetFirewallRule -Name '{name}' -RemoteAddress {addrs}"


def build_remove(cc):
    name = rule_name(cc)
    return f"Remove-NetFirewallRule -Name '{name}' -ErrorAction SilentlyContinue"


def build_remove_country(cc):
    code = validate_cc(cc)
    if code is None:
        raise ValueError("invalid country code")
    prefix = config.FIREWALL_RULE_PREFIX + code
    return (
        f"Get-NetFirewallRule -Group '{config.FIREWALL_RULE_GROUP}' -ErrorAction SilentlyContinue "
        f"| Where-Object {{ $_.Name -eq '{prefix}' -or $_.Name -like '{prefix}-*' }} "
        f"| Remove-NetFirewallRule -ErrorAction SilentlyContinue"
    )


def build_create_chunks(cc, chunks):
    code = validate_cc(cc)
    if code is None:
        raise ValueError("invalid country code")
    stmts = [build_remove_country(code)]
    for rname, cidrs in chunks:
        addrs = _ps_array(cidrs)
        stmts.append(
            f"New-NetFirewallRule -Name '{rname}' -DisplayName '{rname}' "
            f"-Group '{config.FIREWALL_RULE_GROUP}' -Direction Outbound -Action Block "
            f"-Profile Any -Enabled True -RemoteAddress {addrs} "
            f"-Description '{RULE_DESCRIPTION}' | Out-Null"
        )
    return "; ".join(stmts)


def build_ranges_display(cc, cidrs, chunk_size=None):
    chunks = chunk_cidrs(cc, cidrs, chunk_size=chunk_size)
    first_name, first_cidrs = chunks[0]
    shown = ", ".join(first_cidrs[:DISPLAY_MAX_RANGES])
    total = sum(len(c) for _, c in chunks)
    shown_count = min(len(first_cidrs), DISPLAY_MAX_RANGES)
    rem_ranges = total - shown_count
    rem_rules = len(chunks) - 1
    if rem_ranges > 0 or rem_rules > 0:
        shown += f" ... (+{rem_ranges} more ranges in {rem_rules} more rules)"
    return (f"New-NetFirewallRule -Name {first_name} -Group {config.FIREWALL_RULE_GROUP} "
            f"-Direction Outbound -Action Block -RemoteAddress {shown}")


def build_display(cc, ips, update=False):
    """Readable one-line preview for the UI. At most 10 IPs shown.
    update=True shows the Set-NetFirewallRule form (the rule already exists)."""
    name = rule_name(cc)
    checked = _checked_ips(ips)
    shown = ", ".join(checked[:DISPLAY_MAX_IPS])
    if len(checked) > DISPLAY_MAX_IPS:
        shown += f" ... (+{len(checked) - DISPLAY_MAX_IPS} more)"
    if update:
        return f"Set-NetFirewallRule -Name {name} -RemoteAddress {shown}"
    return (f"New-NetFirewallRule -Name {name} -Group {config.FIREWALL_RULE_GROUP} "
            f"-Direction Outbound -Action Block -RemoteAddress {shown}")


# ---------------------------------------------------------------- operations

def _result(ok, message, dry_run, name, ip_count, display):
    return {"ok": ok, "message": message, "dry_run": dry_run, "rule_name": name,
            "ip_count": ip_count, "command_display": display}


def rule_exists(cc):
    """True if any GeoTrench-<CC> or GeoTrench-<CC>-NN rule in our group exists."""
    if validate_cc(cc) is None or not is_admin():
        return False
    name = rule_name(cc)
    # "Not found" is a normal False: SilentlyContinue + exit 0 so it never logs "PowerShell failed".
    ok, out, _ = _run_ps(
        f"@(Get-NetFirewallRule -Group '{config.FIREWALL_RULE_GROUP}' -ErrorAction SilentlyContinue "
        f"| Where-Object {{ $_.Name -eq '{name}' -or $_.Name -like '{name}-*' }}).Count; exit 0"
    )
    return ok and out.strip() not in ("", "0")


def _apply(cc, ips, force=False):
    code = validate_cc(cc)
    if code is None:
        return _result(False, "Invalid country code.", True, None, 0, None)
    name = rule_name(code)
    allowed, _skipped = filter_ips(ips)
    if not allowed:
        return _result(True, "No real IPs to block yet; rule will be created when one appears.",
                       not (force or _enforced()), name, 0, None)
    enforce = force or _enforced()
    with _lock:
        exists = rule_exists(code)  # False when not admin, so dry runs preview New-NetFirewallRule
        display = build_display(code, allowed, update=exists)
        if not enforce:
            return _result(True, "Dry run: firewall rule not sent.", True, name, len(allowed), display)
        script = build_update(code, allowed) if exists else build_create(code, allowed)
        ok, _, _ = _run_ps(script)
    if not ok:
        return _result(False, "Firewall rule could not be created.", False, name, len(allowed), display)
    return _result(True, "Firewall rule applied.", False, name, len(allowed), display)


def apply_rule(cc, ips):
    try:
        return _apply(cc, ips)
    except Exception:
        log.exception("apply_rule failed")
        return _result(False, "Firewall rule could not be created.", True, None, 0, None)


def _ranges_result(ok, message, dry_run, rule_names, range_count, apply_ms, display):
    return {
        "ok": ok,
        "message": message,
        "dry_run": dry_run,
        "rule_names": list(rule_names or []),
        "range_count": range_count,
        "apply_ms": apply_ms,
        "command_display": display,
    }


def apply_ranges(cc, cidrs):
    """Validate CIDRs with strict=True, chunk into GeoTrench-<CC>-NN rules, remove prior GeoTrench-<CC>*
    rules in group GeoTrench first, and apply. Raises ValueError on invalid country code or CIDR."""
    started = time.perf_counter()
    code = validate_cc(cc)
    if code is None:
        raise ValueError("invalid country code")
    chunks = chunk_cidrs(code, cidrs)
    rule_names = [name for name, _ in chunks]
    total_ranges = sum(len(c) for _, c in chunks)
    display = build_ranges_display(code, [c for _, chunk in chunks for c in chunk])
    enforce = _enforced()
    with _lock:
        if not enforce:
            elapsed = round((time.perf_counter() - started) * 1000, 1)
            return _ranges_result(True, "Dry run: firewall rules not sent.", True,
                                  rule_names, total_ranges, elapsed, display)
        script = build_create_chunks(code, chunks)
        ok, _, _ = _run_ps(script)
    elapsed = round((time.perf_counter() - started) * 1000, 1)
    if not ok:
        return _ranges_result(False, "Firewall rules could not be created.", False,
                              rule_names, total_ranges, elapsed, display)
    return _ranges_result(True, "Firewall rules applied.", False,
                          rule_names, total_ranges, elapsed, display)


def _remove(cc, force=False):
    code = validate_cc(cc)
    if code is None:
        return _result(False, "Invalid country code.", True, None, 0, None)
    name = rule_name(code)
    display = f"Remove-NetFirewallRule -Name {name}*"
    if not (force or _enforced()):
        return _result(True, "Dry run: firewall rule not removed.", True, name, 0, display)
    with _lock:
        # Removing a rule that is already gone is fine; success is judged by rule_exists() below.
        _run_ps(build_remove_country(code) + "; exit 0")
        gone = not rule_exists(code)
    if not gone:
        return _result(False, "Firewall rule could not be removed.", False, name, 0, display)
    return _result(True, "Firewall rule removed.", False, name, 0, display)


def remove_country(cc):
    """Remove the plain GeoTrench-<CC> rule and every GeoTrench-<CC>-NN rule in our group."""
    try:
        return _remove(cc)
    except Exception:
        log.exception("remove_country failed")
        return _result(False, "Firewall rule could not be removed.", True, None, 0, None)


def remove_rule(cc):
    return remove_country(cc)


_LIST_SCRIPT = (
    f"$rules = Get-NetFirewallRule -Group '{config.FIREWALL_RULE_GROUP}' -ErrorAction SilentlyContinue "
    f"| Where-Object {{ $_.Name -like '{config.FIREWALL_RULE_PREFIX}*' }}; "
    "$out = foreach ($r in $rules) { $f = $r | Get-NetFirewallAddressFilter; "
    "[pscustomobject]@{ name = $r.Name; enabled = [string]$r.Enabled; direction = [string]$r.Direction; "
    "action = [string]$r.Action; remote = @($f.RemoteAddress) } }; "
    "if ($out) { ConvertTo-Json -InputObject @($out) -Depth 3 -Compress }; exit 0"
)


def _parse_rules_json(text):
    """Parse ConvertTo-Json output, handling the single-object vs array quirk."""
    text = (text or "").strip()
    if not text:
        return []
    data = json.loads(text)
    if isinstance(data, dict):
        data = [data]
    rules = []
    for r in data:
        if not isinstance(r, dict):
            continue
        name = str(r.get("name") or "")
        remote = r.get("remote")
        if remote is None:
            remote = []
        elif isinstance(remote, str):
            remote = [remote]
        rules.append({
            "name": name,
            "country_code": parse_rule_cc(name),
            "enabled": str(r.get("enabled")).lower() == "true",
            "direction": r.get("direction"),
            "action": r.get("action"),
            "remote_addresses": [str(a) for a in remote],
        })
    return rules


def get_rules():
    """Existing Geo-Trench rules (admin only, any mode). [] on errors."""
    if not is_admin():
        return []
    try:
        ok, out, _ = _run_ps(_LIST_SCRIPT)
        return _parse_rules_json(out) if ok else []
    except Exception:
        log.exception("get_rules failed")
        return []


_SWEEP_SCRIPT = (
    f"Get-NetFirewallRule -Group '{config.FIREWALL_RULE_GROUP}' -ErrorAction SilentlyContinue "
    f"| Where-Object {{ $_.Name -like '{config.FIREWALL_RULE_PREFIX}*' }} "
    "| Remove-NetFirewallRule -ErrorAction SilentlyContinue; exit 0"
)


def sweep_all():
    """Remove every GeoTrench-* rule in group GeoTrench (and nothing else). Admin only.
    Returns the names that were removed."""
    if not is_admin():
        return []
    try:
        with _lock:
            before = {r["name"] for r in get_rules()}
            if not before:
                return []
            _run_ps(_SWEEP_SCRIPT)
            after = {r["name"] for r in get_rules()}
        return sorted(before - after)
    except Exception:
        log.exception("sweep_all failed")
        return []


# ---------------------------------------------------------------- connection reset

MIB_TCP_STATE_DELETE_TCB = 12


class MIB_TCPROW(ctypes.Structure):
    _fields_ = [
        ("dwState", ctypes.c_uint32),
        ("dwLocalAddr", ctypes.c_uint32),
        ("dwLocalPort", ctypes.c_uint32),
        ("dwRemoteAddr", ctypes.c_uint32),
        ("dwRemotePort", ctypes.c_uint32),
    ]


def _ipv4_dword(ip):
    """IPv4 string -> DWORD holding the address in network byte order in memory."""
    return struct.unpack("<I", socket.inet_aton(ip))[0]


def _make_tcp_row(local_ip, local_port, remote_ip, remote_port):
    return MIB_TCPROW(
        MIB_TCP_STATE_DELETE_TCB,
        _ipv4_dword(local_ip), socket.htons(int(local_port)) & 0xFFFF,
        _ipv4_dword(remote_ip), socket.htons(int(remote_port)) & 0xFFFF,
    )


def _set_tcp_entry(row):
    """Thin wrapper over iphlpapi.SetTcpEntry (mocked in tests). Returns the Win32 error code (0 = OK)."""
    return ctypes.windll.iphlpapi.SetTcpEntry(ctypes.byref(row))


def reset_tcp_connections(conns):
    """Reset existing IPv4 TCP connections (DELETE_TCB). Returns the number successfully reset.

    Only when enforced AND RESET_CONNECTIONS_ON_GEOFENCE. Remote IPs must pass filter_ips, so local,
    gateway, DNS and never-block addresses are never touched. IPv6 is skipped. Never raises.
    """
    try:
        if not (config.RESET_CONNECTIONS_ON_GEOFENCE and _enforced()):
            return 0
        conns = list(conns or [])
        allowed, _ = filter_ips([c.get("remote_ip") for c in conns])
        allowed = set(allowed)
        reset = skipped = 0
        for c in conns:
            remote = _canonical_ip(c.get("remote_ip"))
            local = _canonical_ip(c.get("local_ip"))
            if (c.get("family") == "ipv6" or remote is None or local is None
                    or ":" in remote or ":" in local):
                skipped += 1  # IPv6 (or unparseable): not supported by SetTcpEntry
                continue
            if remote not in allowed:
                skipped += 1
                continue
            try:
                rc = _set_tcp_entry(_make_tcp_row(local, c.get("local_port"), remote, c.get("remote_port")))
            except Exception as e:
                log.debug("TCP reset raised for remote port %s: %s", c.get("remote_port"), type(e).__name__)
                continue
            if rc == 0:
                reset += 1
            else:
                log.debug("TCP reset failed (code %s) for remote port %s", rc, c.get("remote_port"))
        if skipped:
            log.debug("TCP reset skipped %d connection(s) (IPv6 or not blockable)", skipped)
        return reset
    except Exception:
        log.exception("reset_tcp_connections failed")
        return 0


# ---------------------------------------------------------------- manual admin smoke test

SELF_TEST_CC = "ZZ"
SELF_TEST_IPS = ("45.33.32.156", "45.33.32.157")  # scanme.nmap.org range; harmless to block briefly


def self_test(keep=False):
    """Create, list, update, list, and (unless keep) remove the GeoTrench-ZZ rule.
    Bypasses dry-run ONLY when running as administrator."""
    steps = {}
    if not is_admin():
        print("[self_test] Not running as administrator: nothing will be sent (dry run).")
    force = is_admin()

    def names_and_ips():
        return {r["name"]: r["remote_addresses"] for r in get_rules()}

    print(f"[self_test] 1. Create {rule_name(SELF_TEST_CC)} blocking {SELF_TEST_IPS[0]}")
    steps["create"] = _apply(SELF_TEST_CC, [SELF_TEST_IPS[0]], force=force)
    print("[self_test]    ->", steps["create"]["message"])

    print("[self_test] 2. List rules")
    steps["list_after_create"] = names_and_ips()
    print("[self_test]    ->", steps["list_after_create"])

    print(f"[self_test] 3. Update to block {SELF_TEST_IPS[0]} and {SELF_TEST_IPS[1]}")
    steps["update"] = _apply(SELF_TEST_CC, list(SELF_TEST_IPS), force=force)
    print("[self_test]    ->", steps["update"]["message"])

    print("[self_test] 4. List rules")
    steps["list_after_update"] = names_and_ips()
    print("[self_test]    ->", steps["list_after_update"])

    if keep:
        print("[self_test] 5. keep=True: leaving the rule in place. Remove it with remove_rule('ZZ') or sweep_all().")
    else:
        print(f"[self_test] 5. Remove {rule_name(SELF_TEST_CC)}")
        steps["remove"] = _remove(SELF_TEST_CC, force=force)
        print("[self_test]    ->", steps["remove"]["message"])
        steps["list_after_remove"] = names_and_ips()
        print("[self_test]    ->", steps["list_after_remove"])
    return steps


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)
    print(json.dumps(self_test(keep="--keep" in sys.argv), indent=2))