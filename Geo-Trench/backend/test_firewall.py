"""Plain-script tests for firewall.py. Nothing here executes PowerShell.

Run from backend/:  python test_firewall.py
"""
import sys
from unittest import mock

import config
import firewall as fw

results = []


def check(label, actual, expected):
    ok = actual == expected
    results.append(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] {label}" + ("" if ok else f"  (got {actual!r}, expected {expected!r})"))


def raises_value_error(fn, *args):
    try:
        fn(*args)
    except ValueError:
        return True
    return False


def _no_powershell(*_a, **_k):
    raise AssertionError("test tried to execute PowerShell")


patches = [
    mock.patch.object(fw, "_run_ps", _no_powershell),
    mock.patch.object(fw, "get_never_block", lambda: {"192.0.2.1", "8.8.4.4"}),
    mock.patch.object(config, "ENFORCE_FIREWALL", False),
]
for p in patches:
    p.start()

try:
    # ------------------------------------------------------------ filter_ips
    inputs = [
        "10.0.0.5", "127.0.0.1", "169.254.1.1", "224.0.0.1", "0.0.0.0", "203.0.113.7",
        "8.8.4.4", "abc", "1.1.1.1'; Remove-Item C:\\x", "1.1.1.1,2.2.2.2",
        "2606:4700::1", "1.0.0.6", "1.0.0.5", " 1.0.0.5 ", "1.0.0.5", "::1", "fe80::1",
    ]
    allowed, skipped = fw.filter_ips(inputs)
    reasons = {s["ip"]: s["reason"] for s in skipped}
    check("filter: public IPs kept, deduped, IPv4 before IPv6, numeric order",
          allowed, ["1.0.0.5", "1.0.0.6", "2606:4700::1"])
    for ip, why in [
        ("10.0.0.5", "private/reserved range"), ("127.0.0.1", "private/reserved range"),
        ("169.254.1.1", "private/reserved range"), ("224.0.0.1", "private/reserved range"),
        ("0.0.0.0", "private/reserved range"), ("203.0.113.7", "private/reserved range"),
        ("::1", "private/reserved range"), ("fe80::1", "private/reserved range"),
        ("8.8.4.4", "gateway/DNS/never-block host"),
        ("abc", "invalid"), ("1.1.1.1'; Remove-Item C:\\x", "invalid"), ("1.1.1.1,2.2.2.2", "invalid"),
    ]:
        check(f"filter: {ip!r} skipped as {why}", reasons.get(ip), why)
    check("filter: duplicates are not reported as skipped", sum(1 for s in skipped if s["ip"] == "1.0.0.5"), 0)
    check("filter: 192.0.2.1 (TEST-NET, also never-block) skipped", "192.0.2.1" in fw.filter_ips(["192.0.2.1"])[0], False)
    check("filter: IPv4-mapped IPv6 normalized to IPv4", fw.filter_ips(["::ffff:1.0.0.9"])[0], ["1.0.0.9"])
    check("filter: scoped IPv6 rejected", fw.filter_ips(["2606:4700::1%x'"])[1][0]["reason"], "invalid")
    check("filter: None and empty input are safe", fw.filter_ips(None), ([], []))

    with mock.patch.object(config, "MAX_IPS_PER_RULE", 2):
        a, s = fw.filter_ips(["1.0.0.7", "1.0.0.5", "1.0.0.6", "2606:4700::1"])
    check("filter: cap keeps the first N in sort order", a, ["1.0.0.5", "1.0.0.6"])
    check("filter: over-cap IPs skipped as 'rule size cap'",
          [x for x in s if x["reason"] == "rule size cap"],
          [{"ip": "1.0.0.7", "reason": "rule size cap"}, {"ip": "2606:4700::1", "reason": "rule size cap"}])

    # ------------------------------------------------------------ validate_cc / rule_name
    check("validate_cc: 'de' -> 'DE'", fw.validate_cc("de"), "DE")
    check("validate_cc: ' ru ' -> 'RU'", fw.validate_cc(" ru "), "RU")
    for bad in ("DEU", "D1", "", "D'", None, "D E"):
        check(f"validate_cc: {bad!r} -> None", fw.validate_cc(bad), None)
    check("rule_name: GeoTrench-DE", fw.rule_name("de"), "GeoTrench-DE")
    check("rule_name: bad cc raises ValueError", raises_value_error(fw.rule_name, "D'"), True)

    # ------------------------------------------------------------ builders
    create = fw.build_create("de", ["1.0.0.5", "2606:4700::1"])
    check("build_create: name and display name",
          "-Name 'GeoTrench-DE'" in create and "-DisplayName 'GeoTrench-DE'" in create, True)
    check("build_create: group", "-Group 'GeoTrench'" in create, True)
    check("build_create: outbound block, any profile, enabled",
          all(s in create for s in ("-Direction Outbound", "-Action Block", "-Profile Any", "-Enabled True")), True)
    check("build_create: quoted IP array", "-RemoteAddress @('1.0.0.5','2606:4700::1')" in create, True)
    check("build_create: description", "-Description 'Geo-Trench geofence (auto-expires)'" in create, True)
    check("build_update: Set-NetFirewallRule with array",
          fw.build_update("DE", ["1.0.0.5"]), "Set-NetFirewallRule -Name 'GeoTrench-DE' -RemoteAddress @('1.0.0.5')")
    check("build_remove: Remove-NetFirewallRule",
          fw.build_remove("de"), "Remove-NetFirewallRule -Name 'GeoTrench-DE' -ErrorAction SilentlyContinue")

    for label, fn, args in [
        ("build_create bad cc", fw.build_create, ("D'", ["1.0.0.5"])),
        ("build_create injected IP", fw.build_create, ("DE", ["1.1.1.1'; Remove-Item C:\\x"])),
        ("build_create comma IP", fw.build_create, ("DE", ["1.1.1.1,2.2.2.2"])),
        ("build_create non-canonical IP", fw.build_create, ("DE", ["01.0.0.5"])),
        ("build_create scoped IPv6", fw.build_create, ("DE", ["fe80::1%x"])),
        ("build_create empty list", fw.build_create, ("DE", [])),
        ("build_update bad IP", fw.build_update, ("DE", ["abc"])),
        ("build_remove bad cc", fw.build_remove, ("DEU",)),
        ("build_display bad IP", fw.build_display, ("DE", ["abc"])),
    ]:
        check(f"{label}: raises ValueError", raises_value_error(fn, *args), True)

    many = [f"1.0.0.{i}" for i in range(1, 16)]
    disp = fw.build_display("de", many)
    check("build_display: shows 10 IPs then '(+5 more)'",
          disp.endswith("1.0.0.10 ... (+5 more)") and "1.0.0.11" not in disp, True)
    check("build_display: comma-separated list", "-RemoteAddress 1.0.0.1, 1.0.0.2" in disp, True)
    check("build_display: no truncation when <= 10", "more" in fw.build_display("DE", many[:10]), False)
    check("build_display: update=True shows Set-NetFirewallRule",
          fw.build_display("de", ["1.0.0.5"], update=True), "Set-NetFirewallRule -Name GeoTrench-DE -RemoteAddress 1.0.0.5")

    # ------------------------------------------------------------ mode and dry-run operations
    check("enforcement_mode: ENFORCE_FIREWALL false",
          fw.enforcement_mode(), {"mode": "dry_run", "reason": "ENFORCE_FIREWALL is false"})
    with mock.patch.object(config, "ENFORCE_FIREWALL", True), mock.patch.object(fw, "is_admin", lambda: False):
        check("enforcement_mode: enforce on but not admin",
              fw.enforcement_mode(), {"mode": "dry_run", "reason": "Not running as administrator"})

    r = fw.apply_rule("de", ["1.0.0.5", "10.0.0.1"])
    check("apply_rule (dry run): ok, nothing sent",
          (r["ok"], r["dry_run"], r["message"], r["rule_name"], r["ip_count"]),
          (True, True, "Dry run: firewall rule not sent.", "GeoTrench-DE", 1))
    check("apply_rule (dry run): command_display preview", "GeoTrench-DE" in (r["command_display"] or ""), True)
    r = fw.apply_rule("DE", ["10.0.0.1", "8.8.4.4"])
    check("apply_rule: no real IPs -> ok, ip_count 0, nothing run",
          (r["ok"], r["ip_count"], r["message"]),
          (True, 0, "No real IPs to block yet; rule will be created when one appears."))
    r = fw.apply_rule("D'", ["1.0.0.5"])
    check("apply_rule: bad cc -> ok False", r["ok"], False)
    r = fw.remove_rule("de")
    check("remove_rule (dry run): no-op success", (r["ok"], r["dry_run"]), (True, True))

    # ------------------------------------------------------------ JSON parsing quirk (no PowerShell)
    single = '{"name":"GeoTrench-DE","enabled":"True","direction":"Outbound","action":"Block","remote":"1.0.0.5"}'
    arr = ('[{"name":"GeoTrench-DE","enabled":"True","direction":"Outbound","action":"Block","remote":["1.0.0.5"]},'
           '{"name":"GeoTrench-RU","enabled":"False","direction":"Outbound","action":"Block","remote":[]}]')
    check("parse rules: single object becomes a one-item list",
          fw._parse_rules_json(single),
          [{"name": "GeoTrench-DE", "country_code": "DE", "enabled": True, "direction": "Outbound",
            "action": "Block", "remote_addresses": ["1.0.0.5"]}])
    check("parse rules: array", [(r["country_code"], r["enabled"]) for r in fw._parse_rules_json(arr)],
          [("DE", True), ("RU", False)])
    check("parse rules: empty output", fw._parse_rules_json(""), [])
finally:
    for p in reversed(patches):
        p.stop()

passed = sum(results)
print(f"\n{passed}/{len(results)} passed" + ("" if passed == len(results) else "  <-- FAILURES"))
sys.exit(0 if passed == len(results) else 1)
