"""Tests for insights.build. Run: python test_insights.py"""
import json
import sys

import insights

results = []


def check(label, actual, expected):
    ok = actual == expected
    results.append(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] {label}" + ("" if ok else f"  (got {actual!r}, expected {expected!r})"))


def by_id(items):
    return {i["id"]: i for i in items}


CHROME = {"id": "a1", "process_name": "chrome.exe", "remote_ip": "142.250.80.46", "remote_port": 443,
          "country_code": "US", "asn_org": "Google LLC.", "ancestry": ["explorer.exe", "chrome.exe"],
          "exe": r"C:\Program Files\Google\Chrome\Application\chrome.exe", "first_seen": "2026-11-15T10:00:00+00:00",
          "is_simulated": False}
CHROME2 = {**CHROME, "id": "a2", "remote_ip": "151.101.1.69", "country_code": "DE"}
CODE = {**CHROME, "id": "a3", "process_name": "code.exe"}  # same server as CHROME
USER_APP = {"id": "b1", "process_name": "tool.exe", "remote_ip": "203.0.113.5", "remote_port": 8443,
            "asn_org": "Small Host Ltd", "ancestry": ["explorer.exe", "powershell.exe", "tool.exe"],
            "exe": r"C:\Users\<user>\Downloads\it's tool.exe", "is_simulated": False}
SIM = {**USER_APP, "id": "s1", "is_simulated": True}
SNAP = [CHROME, CHROME2, CODE, USER_APP]

c = by_id(insights.build(CHROME, SNAP))
check("same_app counts other connections and countries", c["same_app"]["text"].startswith("chrome.exe has 1 other connection open right now, to DE."), True)
check("same_destination names the other app", "code.exe also connects to 142.250.80.46" in c["same_destination"]["text"], True)
check("owner: shared host explained, trailing period stripped",
      ("run by Google LLC." in c["owner"]["text"], "hosting company" in c["owner"]["text"]), (True, True))
check("owner: reverse lookup command quoted", c["owner"]["command"], "Resolve-DnsName '142.250.80.46' -Type PTR -ErrorAction SilentlyContinue")
check("port: 443 named", "encrypted web traffic" in c["port"]["text"], True)
check("parent: launcher and chain", c["parent"]["text"].startswith("explorer.exe started chrome.exe."), True)
check("signature: Program Files path single-quoted",
      c["signature"]["command"], r"Get-AuthenticodeSignature 'C:\Program Files\Google\Chrome\Application\chrome.exe' | Format-List Status, SignerCertificate")
check("first_seen shown", "2026-11-15T10:00:00+00:00" in c["first_seen"]["text"], True)
check("no simulated note on real connection", "simulated" in c, False)

u = by_id(insights.build(USER_APP, SNAP))
check("only connection wording", u["same_app"]["text"].startswith("This is tool.exe's only connection"), True)
check("no same_destination when nobody shares it", "same_destination" in u, False)
check("unknown port explained", "isn't a common well-known port" in u["port"]["text"], True)
check("user path -> $env:USERPROFILE, quote doubled",
      u["hash"]["command"], "Get-FileHash (Join-Path $env:USERPROFILE 'Downloads\\it''s tool.exe') -Algorithm SHA256 | Format-List Hash")
check("live command uses the public IP", "-RemoteAddress '203.0.113.5'" in u["live"]["command"], True)
check("no <user> marker or raw username in any output", "<user>" in json.dumps(insights.build(USER_APP, SNAP)), False)

s = by_id(insights.build(SIM, SNAP))
check("simulated: no commands at all", [i["id"] for i in s.values() if "command" in i], [])
check("simulated: demo note present", "simulated" in s, True)

check("other redaction marker -> no file commands",
      [i["id"] for i in insights.build({**USER_APP, "exe": r"C:\x\<redacted>\a.exe"}, []) if i["id"] in ("signature", "hash")], [])
check("bad IP -> no IP commands", [i["id"] for i in insights.build({**USER_APP, "remote_ip": "x; rm"}, []) if "command" in i and "RemoteAddress" in i["command"] + "" or i["id"] == "live"], [])
check("garbage input never raises", insights.build({"ancestry": 5, "remote_port": "x"}, [None]) is not None, True)
check("empty dict works", isinstance(insights.build({}, []), list), True)

print(f"\n{sum(results)}/{len(results)} passed")
sys.exit(0 if all(results) else 1)
