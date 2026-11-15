"""Planted demo connections. Only returned when DEMO_MODE is true. Fully deterministic.

SAFETY: planted threats are simulated and NEVER touch the OS. Their PIDs are
negative and their files do not exist. Any quarantine or firewall code MUST check
conn["is_simulated"] and, when it is True, only dry-run (log what it would do).
"""
import copy

import config
from threats import classify

# 203.0.113.0/24 is a reserved documentation range, so real GeoIP returns nothing
# for it. These overrides give each planted IP a real city with a fictional ASN org.
PLANTED_GEO = {
    "203.0.113.10": {
        "lat": 55.7558, "lng": 37.6173,
        "country_code": "RU", "country_name": "Russia", "city": "Moscow",
        "asn_org": "Taiga Byte Hosting",
    },
    "203.0.113.66": {
        "lat": 22.5431, "lng": 114.0579,
        "country_code": "CN", "country_name": "China", "city": "Shenzhen",
        "asn_org": "Red Lantern Cloud Ltd",
    },
    "203.0.113.99": {
        "lat": 6.5244, "lng": 3.3792,
        "country_code": "NG", "country_name": "Nigeria", "city": "Lagos",
        "asn_org": "Harmattan Net Services",
    },
    "203.0.113.150": {
        "lat": 44.4268, "lng": 26.1025,
        "country_code": "RO", "country_name": "Romania", "city": "Bucharest",
        "asn_org": "Carpathian Edge Networks",
    },
}


def planted_geo(ip):
    """Return the override location for a planted IP, or None."""
    geo = PLANTED_GEO.get(ip)
    return copy.deepcopy(geo) if geo is not None else None

_WINWORD = r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"
_CMD = r"C:\Windows\System32\cmd.exe"
_POWERSHELL = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
_UPDATER = r"C:\Users\<user>\AppData\Roaming\updater.exe"
_PAYLOAD = r"C:\ProgramData\payload.exe"
_SVC_HOST32 = r"C:\Users\<user>\AppData\Local\Temp\svc_host32.exe"
_EXCEL = r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE"
_RUNDLL32 = r"C:\Windows\System32\rundll32.exe"


def _conn(pid, local_port, remote_ip, remote_port, chain):
    """chain: list of (pid, name, exe), root -> leaf. The leaf is the connecting process."""
    leaf_pid, leaf_name, leaf_exe = chain[-1]
    conn = {
        "pid": pid,
        "process_name": leaf_name,
        "exe": leaf_exe,
        "raw_exe": leaf_exe,  # fake path; contains no real username
        "local_ip": "192.168.1.50",
        "local_port": local_port,
        "remote_ip": remote_ip,
        "remote_port": remote_port,
        "ancestry": [name for _, name, _ in chain],
        "ancestry_detail": [{"pid": p, "name": n, "exe": e} for p, n, e in chain],
        "is_simulated": True,
        "geo": planted_geo(remote_ip),
    }
    # Same rules as real traffic: nothing about the verdict is hard-coded.
    conn["threat"] = classify(conn)
    return conn


def get_planted_connections():
    if not config.DEMO_MODE:
        return []
    return [
        # a) Word document drops a shell that launches a dropper on the Metasploit port.
        _conn(-1001, 49731, "203.0.113.10", 4444, [
            (-1101, "winword.exe", _WINWORD),
            (-1102, "cmd.exe", _CMD),
            (-1001, "updater.exe", _UPDATER),
        ]),
        # b) PowerShell runs a payload that phones home on 1337.
        _conn(-1002, 49732, "203.0.113.66", 1337, [
            (-1201, "powershell.exe", _POWERSHELL),
            (-1002, "payload.exe", _PAYLOAD),
        ]),
        # c) A look-alike service running out of Temp, talking IRC.
        _conn(-1003, 49733, "203.0.113.99", 6667, [
            (-1003, "svc_host32.exe", _SVC_HOST32),
        ]),
        # d) A hijacked system binary: Excel abuses rundll32 to reach out on 5555.
        #    Its exe is under C:\Windows, so it is protected: demos the protected-path lock.
        _conn(-1004, 49734, "203.0.113.150", 5555, [
            (-1401, "excel.exe", _EXCEL),
            (-1004, "rundll32.exe", _RUNDLL32),
        ]),
    ]
