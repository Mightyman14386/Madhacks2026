"""Deterministic "explore further" insights for each connection.

build(conn, snapshot) -> [{"id", "title", "text", "command"?}]
- Built only from fields the API already returns (redacted exe, ancestry names, public remote IP,
  GeoIP/ASN), plus counts over the same snapshot. No raw_exe, no local IPs, no lookups, no randomness.
- "command" is a PowerShell line the user can copy and run themselves; GeoTracker never runs it.
  Paths under the redacted C:\\Users\\<user>\\ become $env:USERPROFILE; values are single-quoted.
- Never raises: on bad input it returns whatever insights were built so far (possibly []).
"""
import ipaddress
import re

PORT_NAMES = {
    80: "plain web traffic (HTTP)", 443: "encrypted web traffic (HTTPS)", 53: "DNS lookups",
    853: "encrypted DNS", 993: "encrypted email (IMAP)", 995: "encrypted email (POP3)",
    587: "sending email (SMTP)", 22: "SSH remote login", 3389: "Remote Desktop",
    5228: "Google app notifications", 5222: "chat (XMPP)", 3478: "voice/video calls (STUN/TURN)",
    1337: "hacking tools", 4444: "the Metasploit hacking toolkit", 31337: "old backdoors",
    6667: "IRC chat, also used by botnets", 5555: "Android debugging / remote control",
}

# Large shared hosting and CDN networks: the owner is the host, not the website.
SHARED_HOSTS = ("amazon", "google", "microsoft", "cloudflare", "akamai", "fastly", "digitalocean",
                "linode", "ovh", "hetzner", "oracle", "alibaba", "tencent", "edgecast")

_USER_PREFIX = re.compile(r"^[a-zA-Z]:\\Users\\<user>\\", re.IGNORECASE)


def _q(value):
    """PowerShell single-quoted literal: only ' is special inside, doubled to escape."""
    return "'" + str(value).replace("'", "''") + "'"


def _ps_path(exe):
    """Redacted exe path -> PowerShell expression, or None if it can't be expressed safely."""
    if not exe or not isinstance(exe, str):
        return None
    m = _USER_PREFIX.match(exe)
    rest = exe[m.end():] if m else exe
    if "<" in rest or ">" in rest or "\n" in rest:
        return None  # another redaction marker or odd text: don't build a command
    return f"(Join-Path $env:USERPROFILE {_q(rest)})" if m else _q(exe)


def _public_ip(ip):
    try:
        return str(ipaddress.ip_address(str(ip)))
    except ValueError:
        return None


def build(conn, snapshot=()):
    out = []
    try:
        name = conn.get("process_name") or "This app"
        ip = _public_ip(conn.get("remote_ip"))
        port = conn.get("remote_port")
        sim = bool(conn.get("is_simulated"))
        others = [c for c in snapshot if c.get("id") != conn.get("id")]

        # 1. The app's other traffic right now.
        same_app = [c for c in others if c.get("process_name") == conn.get("process_name")]
        if same_app:
            countries = sorted({c.get("country_code") for c in same_app if c.get("country_code")})
            text = (f"{name} has {len(same_app)} other connection{'s' if len(same_app) != 1 else ''} open right now"
                    + (f", to {', '.join(countries)}." if countries else "."))
            text += " Compare them: an app that suddenly talks to many new places is worth a closer look."
        else:
            text = f"This is {name}'s only connection right now. One steady connection is typical for update checks and sync."
        out.append({"id": "same_app", "title": "What else is this app doing?", "text": text})

        # 2. Other apps using the same server.
        same_dest = sorted({c.get("process_name") for c in others if c.get("remote_ip") == conn.get("remote_ip")
                            and c.get("process_name") and c.get("process_name") != conn.get("process_name")})
        if same_dest:
            out.append({"id": "same_destination", "title": "Other apps use this server too",
                        "text": f"{', '.join(same_dest[:5])} also connect{'s' if len(same_dest) == 1 else ''} to "
                                f"{ip}. A server shared with apps you trust is usually a common service."})

        # 3. Who runs the destination.
        org = (conn.get("asn_org") or "").rstrip(".")
        if org:
            text = f"The address belongs to a network run by {org}."
            if any(h in org.lower() for h in SHARED_HOSTS):
                text += (" That is a large cloud or CDN provider shared by thousands of sites, so it tells you the"
                         " hosting company, not which website or service the app is using.")
            else:
                text += " Search the name together with the app's name to see whether they are normally linked."
        else:
            text = "GeoTracker doesn't know who runs this network. A reverse lookup sometimes shows a server name."
        item = {"id": "owner", "title": "Who runs this server?", "text": text}
        if ip and not sim:
            item["command"] = f"Resolve-DnsName {_q(ip)} -Type PTR -ErrorAction SilentlyContinue"
        out.append(item)

        # 4. What the port usually means.
        try:
            p = int(port)
        except (TypeError, ValueError):
            p = None
        if p is not None:
            known = PORT_NAMES.get(p)
            out.append({"id": "port", "title": f"What is port {p}?",
                        "text": (f"Port {p} is normally used for {known}." if known else
                                 f"Port {p} isn't a common well-known port. Search \"port {p}\" with {name} to see"
                                 " whether the app documents it.")
                                + " The port says what kind of service is expected, not what data is sent."})

        # 5. How it started.
        chain = [n for n in (conn.get("ancestry") or []) if isinstance(n, str)]
        if len(chain) >= 2:
            out.append({"id": "parent", "title": "Do you recognise how it started?",
                        "text": f"{chain[-2]} started {chain[-1]}. Full chain: {' -> '.join(chain)}."
                                " If you don't recognise a step, look it up before trusting the app."})

        # 6. Is the program file signed? (real, locatable files only)
        path = None if sim else _ps_path(conn.get("exe"))
        if path:
            out.append({"id": "signature", "title": "Is the program signed?",
                        "text": "A valid digital signature shows who published the file and that it wasn't changed."
                                " Unsigned isn't proof of malware, but well-known apps are almost always signed.",
                        "command": f"Get-AuthenticodeSignature {path} | Format-List Status, SignerCertificate"})
            out.append({"id": "hash", "title": "Check the file's reputation",
                        "text": "This prints the file's SHA-256 fingerprint. You can search that fingerprint on a"
                                " reputation site such as VirusTotal; searching a hash doesn't upload the file.",
                        "command": f"Get-FileHash {path} -Algorithm SHA256 | Format-List Hash"})

        # 7. Watch it live.
        if ip and not sim:
            out.append({"id": "live", "title": "Watch it live",
                        "text": "Lists this connection from Windows itself, so you can check it's still open and"
                                " which process owns it.",
                        "command": f"Get-NetTCPConnection -RemoteAddress {_q(ip)} -ErrorAction SilentlyContinue"
                                   " | Format-Table LocalPort, RemotePort, State, OwningProcess"})

        # 8. When it appeared.
        if conn.get("first_seen"):
            out.append({"id": "first_seen", "title": "When did it start?",
                        "text": f"GeoTracker first saw this connection at {conn['first_seen']} (UTC). If that's right"
                                " after you installed or opened something, that is the likely cause."})

        if sim:
            out.append({"id": "simulated", "title": "This is a demo connection",
                        "text": "It was planted by GeoTracker's demo mode, so Windows commands won't find it."
                                " On a real connection this section also offers commands to check it yourself."})
    except Exception:
        pass
    return out
