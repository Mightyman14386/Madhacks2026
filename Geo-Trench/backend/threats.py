"""Deterministic threat rules. The backend is the source of truth for verdicts.

classify(conn) never raises; malformed input simply fires no rules.
"""
import ntpath

SUSPICIOUS_PORTS = {
    4444: "a default port for the Metasploit hacking toolkit",
    1337: "a port favored by hacking tools",
    31337: "a classic backdoor port",
    6667: "the chat (IRC) port that botnets use to receive commands",
    5555: "a port often used for remote control of devices",
}

OFFICE_APPS = {
    "winword.exe": "Microsoft Word",
    "excel.exe": "Microsoft Excel",
    "powerpnt.exe": "Microsoft PowerPoint",
    "outlook.exe": "Microsoft Outlook",
}

SHELLS = {
    "cmd.exe": "the Command Prompt",
    "powershell.exe": "PowerShell",
    "pwsh.exe": "PowerShell",
    "wscript.exe": "Windows Script Host",
    "cscript.exe": "Windows Script Host",
    "mshta.exe": "the Microsoft HTML Application host",
}

# Well-known apps that are routinely launched from a terminal on a developer machine.
# shell_spawn alone never flags these. Edit freely; names are compared lowercase.
BENIGN_APPS = {
    # browsers
    "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe",
    # editors / dev tools
    "code.exe", "code - insiders.exe", "git.exe", "git-remote-https.exe", "ssh.exe",
    "node.exe", "python.exe", "pythonw.exe", "python3.exe",
    "python3.11.exe", "python3.12.exe", "python3.13.exe", "uvicorn.exe", "claude.exe",
    # terminal plumbing
    "conhost.exe", "openconsole.exe", "windowsterminal.exe",
    # chat / media / sync
    "teams.exe", "ms-teams.exe", "slack.exe", "discord.exe", "spotify.exe", "onedrive.exe",
}

_SEVERITY_ORDER = ("suspicious_port", "office_spawn", "shell_spawn", "risky_location")


def _final_and_ancestors(conn):
    ancestry = [str(n).lower() for n in (conn.get("ancestry") or []) if n]
    final = str(conn.get("process_name") or (ancestry[-1] if ancestry else "unknown")).lower()
    ancestors = ancestry[:-1] if ancestry and ancestry[-1] == final else ancestry
    return final, ancestors


def _first_match(names, table):
    # Closest ancestor first: that's the one that most directly launched the process.
    for name in reversed(names):
        if name in table:
            return name
    return None


def _port_hit(conn):
    for key in ("remote_port", "local_port"):
        try:
            port = int(conn.get(key))
        except (TypeError, ValueError):
            continue
        if port in SUSPICIOUS_PORTS:
            return port
    return None


def _risky_folder(raw_exe):
    if not raw_exe:
        return None
    path = ntpath.normpath(str(raw_exe).replace("/", "\\")).lower()
    parts = [p for p in path.split("\\") if p]
    folders = parts[:-1]  # ignore the filename itself
    if folders[:3] == ["c:", "users", "public"]:
        return "the shared Public folder"
    if "temp" in folders:
        return "a Temp folder"
    if "downloads" in folders:
        return "the Downloads folder"
    return None


def classify(conn):
    try:
        conn = conn or {}
        final, ancestors = _final_and_ancestors(conn)
        fired, reasons = [], {}

        port = _port_hit(conn)
        if port is not None:
            fired.append("suspicious_port")
            reasons["suspicious_port"] = (
                f"Connected over port {port}, {SUSPICIOUS_PORTS[port]}."
            )

        office = _first_match(ancestors, OFFICE_APPS)
        if office and final not in OFFICE_APPS:
            fired.append("office_spawn")
            reasons["office_spawn"] = (
                f"Launched by {OFFICE_APPS[office]}, which is unusual for a network connection. "
                "Documents that start other programs are a common way malware gets in."
            )

        shell = _first_match(ancestors, SHELLS)
        if shell and final not in SHELLS:
            fired.append("shell_spawn")
            reasons["shell_spawn"] = (
                f"Started from {SHELLS[shell]}, a tool attackers often use to run hidden commands."
            )

        folder = _risky_folder(conn.get("raw_exe"))
        if folder:
            fired.append("risky_location")
            reasons["risky_location"] = (
                f"The program is running from {folder}, where legitimate software rarely lives."
            )

        # False-positive control: shell ancestry alone is normal for well-known apps.
        if fired == ["shell_spawn"] and final in BENIGN_APPS:
            fired = []

        if not fired:
            return {"status": "safe", "severity": "low", "rules_fired": [], "reasons": []}

        f = set(fired)
        if "office_spawn" in f and ({"suspicious_port", "shell_spawn"} & f):
            severity = "critical"
        elif "office_spawn" in f or {"suspicious_port", "risky_location"} <= f:
            severity = "high"
        elif "suspicious_port" in f or "risky_location" in f:
            severity = "medium"
        else:  # shell_spawn alone, on a process not in BENIGN_APPS
            severity = "low"

        ordered = [r for r in _SEVERITY_ORDER if r in f]
        return {
            "status": "unsafe",
            "severity": severity,
            "rules_fired": ordered,
            "reasons": [reasons[r] for r in ordered],
        }
    except Exception:
        return {"status": "safe", "severity": "low", "rules_fired": [], "reasons": []}
