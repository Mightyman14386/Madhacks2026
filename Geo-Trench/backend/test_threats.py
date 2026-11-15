"""Plain-script tests for threats.classify() and the planted scenarios.

Run from backend/:  python test_threats.py
"""
import sys

import config
import scenarios
from threats import classify

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def conn(process_name, ancestry, raw_exe, remote_port, local_port=50000):
    return {
        "process_name": process_name,
        "raw_exe": raw_exe,
        "ancestry": ancestry,
        "ancestry_detail": [{"pid": None, "name": n, "exe": None} for n in ancestry],
        "remote_port": remote_port,
        "local_port": local_port,
    }


results = []


def check(label, result, status, severity=None, min_severity=None):
    ok = result["status"] == status
    if severity is not None:
        ok = ok and result["severity"] == severity
    if min_severity is not None:
        ok = ok and SEVERITY_RANK[result["severity"]] >= SEVERITY_RANK[min_severity]
    if status == "unsafe":
        ok = ok and bool(result["reasons"]) and len(result["reasons"]) == len(result["rules_fired"])
    else:
        ok = ok and result["rules_fired"] == [] and result["reasons"] == []
    results.append(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] {label}")
    print(f"       -> {result['status']} / {result['severity']} / {result['rules_fired']}")
    for r in result["reasons"]:
        print(f"          - {r}")


check(
    "Excel-spawned cmd on port 4444 is critical",
    classify(conn("cmd.exe", ["explorer.exe", "EXCEL.EXE", "cmd.exe"], r"C:\Windows\System32\cmd.exe", 4444)),
    "unsafe", severity="critical",
)
check(
    "Chrome with PowerShell ancestry on 443 is safe (false-positive control)",
    classify(conn(
        "chrome.exe",
        ["explorer.exe", "Code.exe", "powershell.exe", "chrome.exe"],
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        443,
    )),
    "safe", severity="low",
)
check(
    "Exe in Temp on port 6667 is medium or higher",
    classify(conn(
        "svc.exe", ["explorer.exe", "svc.exe"],
        r"C:\Users\someone\AppData\Local\Temp\svc.exe", 6667,
    )),
    "unsafe", min_severity="medium",
)
check(
    "Plain Edge connection on 443 is safe",
    classify(conn(
        "msedge.exe", ["explorer.exe", "msedge.exe"],
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", 443,
    )),
    "safe", severity="low",
)

config.DEMO_MODE = True  # planted scenarios only exist in demo mode
planted = scenarios.get_planted_connections()
if len(planted) != 4:
    results.append(False)
    print(f"[FAIL] expected 4 planted connections, got {len(planted)}")
for p in planted:
    check(
        f"Planted {p['process_name']} (pid {p['pid']}) is unsafe",
        p["threat"], "unsafe",
    )
    if p["pid"] == -1004:
        rules_ok = {"office_spawn", "suspicious_port"} <= set(p["threat"]["rules_fired"])
        results.append(rules_ok)
        print(f"[{'PASS' if rules_ok else 'FAIL'}] Planted rundll32.exe fires office_spawn + suspicious_port")
    geo_ok = p["is_simulated"] is True and p["geo"] is not None
    results.append(geo_ok)
    print(f"[{'PASS' if geo_ok else 'FAIL'}] Planted {p['process_name']} is simulated with override geo"
          f" ({p['geo']['city'] if p['geo'] else None})")

passed = sum(results)
print(f"\n{passed}/{len(results)} passed" + ("" if passed == len(results) else "  <-- FAILURES"))
sys.exit(0 if passed == len(results) else 1)
