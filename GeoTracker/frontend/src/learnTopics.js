// "Keep learning": next steps for learning about networks, security risks and where servers are.
// Teaching content only, written by people. Topics are picked deterministically from fields the backend
// already returned for the selected connection; verdicts still come only from the backend.
// Every link was checked to load (MDN, Wikipedia, MITRE ATT&CK, Microsoft Learn, TeleGeography).

const MDN = "https://developer.mozilla.org/en-US/docs/";
const WIKI = "https://en.wikipedia.org/wiki/";
const ATTACK = "https://attack.mitre.org/techniques/";

export const AREAS = {security: "Security risks", places: "Servers around the world", network: "How networks work"};

// Well-known Windows program names. If one runs from outside a Windows folder the backend marks it
// not protected, which is worth learning about (attackers borrow these names).
const WINDOWS_NAMES = new Set(["svchost.exe", "explorer.exe", "lsass.exe", "csrss.exe", "services.exe", "winlogon.exe",
  "rundll32.exe", "dllhost.exe", "taskhostw.exe", "smss.exe", "spoolsv.exe", "conhost.exe"]);
const SHARED_HOSTS = ["amazon", "google", "microsoft", "cloudflare", "akamai", "fastly", "digitalocean", "linode",
  "ovh", "hetzner", "oracle", "alibaba", "tencent", "edgecast"];
const FIBER_KM_PER_MS = 200; // light in glass fibre travels about 200 km per millisecond
const FAR_KM = 4000;         // beyond this, traffic very likely crosses an ocean or several countries

export function distanceKm(a, b) {
  const num = v => v !== null && v !== undefined && v !== "" && Number.isFinite(+v);
  const ok = p => p && num(p.lat) && num(p.lng);
  if (!ok(a) || !ok(b)) return null;
  const rad = d => d * Math.PI / 180, R = 6371;
  const dLat = rad(b.lat - a.lat), dLng = rad(b.lng - a.lng);
  const h = Math.sin(dLat / 2) ** 2 + Math.cos(rad(a.lat)) * Math.cos(rad(b.lat)) * Math.sin(dLng / 2) ** 2;
  return 2 * R * Math.asin(Math.min(1, Math.sqrt(h)));
}

const fmt = n => Math.round(n).toLocaleString("en-US");
const ipOk = ip => typeof ip === "string" && /^[0-9a-fA-F:.]+$/.test(ip); // only digits, hex, dots, colons

export function pickLessons(c, origin, max = 6) {
  if (!c) return [];
  const out = [];
  const add = (area, id, title, hook, body, link, tryIt) => out.push({area, id, title, hook, body, link, tryIt});
  const fired = new Set(c.rules_fired || []);
  const name = c.process_name || "This app";
  const port = Number(c.remote_port);
  const org = (c.asn_org || "").replace(/\.+$/, "");
  const shared = SHARED_HOSTS.some(h => org.toLowerCase().includes(h));
  const ip = ipOk(c.remote_ip) ? c.remote_ip : null;
  const live = ip && !c.is_simulated; // demo addresses don't exist, so no "try it" commands for them
  const km = distanceKm(origin, c);
  const where = [c.city, c.country_name || c.country_code].filter(Boolean).join(", ");

  // ---- Security risks (backend findings first, then patterns worth knowing about)
  if (fired.has("office_spawn"))
    add("security", "phishing_attachment", "Malicious documents (phishing attachments)",
      `${name} was started by an Office app, the pattern this attack leaves behind.`,
      "Attackers email a document that asks you to \"enable content\". A macro then starts a program that downloads more malware. It is one of the most common ways attacks begin.",
      {label: "MITRE ATT&CK T1566.001: Spearphishing Attachment", url: ATTACK + "T1566/001/"});
  if (fired.has("shell_spawn"))
    add("security", "script_interpreter", "Attacks that use command shells",
      `A command shell appears in how ${name} started.`,
      "PowerShell and cmd are built into Windows, so attackers use them to run commands without bringing their own tools (\"living off the land\"). Defenders watch which programs shells start.",
      {label: "MITRE ATT&CK T1059: Command and Scripting Interpreter", url: ATTACK + "T1059/"});
  if (fired.has("suspicious_port"))
    add("security", "nonstandard_port", "Command-and-control on unusual ports",
      `This connection uses port ${port}, which hacking tools often use by default.`,
      "Malware that has infected a computer \"calls home\" to a command-and-control (C2) server for instructions. Lazy or default setups often use well-known tool ports, which makes them easier to spot.",
      {label: "MITRE ATT&CK T1571: Non-Standard Port", url: ATTACK + "T1571/"});
  if (fired.has("risky_location"))
    add("security", "user_execution", "Tricking people into running programs",
      `${name} runs from a Temp, Downloads or shared folder.`,
      "Many attacks need you to run something: a fake installer, a \"document\" that is really a program, or a cracked app. Those files usually start from Downloads or Temp.",
      {label: "MITRE ATT&CK T1204: User Execution", url: ATTACK + "T1204/"});
  if (WINDOWS_NAMES.has(String(c.process_name || "").toLowerCase()) && c.is_protected === false)
    add("security", "masquerading", "Malware that borrows Windows names",
      `${name} is a Windows program name, but this copy doesn't run from a Windows folder.`,
      "Malware often names itself svchost.exe or explorer.exe to blend in. The real ones live in C:\\Windows. The name alone proves nothing; the location matters.",
      {label: "MITRE ATT&CK T1036: Masquerading", url: ATTACK + "T1036/"});
  if (port === 80)
    add("security", "plaintext", "Unencrypted web traffic",
      "This connection uses port 80, plain HTTP.",
      "Without encryption, anyone on the network path (public Wi-Fi, a compromised router) can read or change the data. Most sites now use HTTPS; apps still using HTTP are often update checks or old software.",
      {label: "MDN: HTTPS", url: MDN + "Glossary/HTTPS"});
  if (shared && port === 443)
    add("security", "trusted_cloud", "Why \"it's a big cloud company\" isn't proof of safety",
      `This server is run by ${org}.`,
      "Anyone can rent servers from big cloud providers, attackers included. Some malware deliberately talks to popular cloud services because that traffic looks normal and is rarely blocked.",
      {label: "MITRE ATT&CK T1102: Web Service", url: ATTACK + "T1102/"});

  // ---- Servers around the world
  if (km != null) {
    const rtt = 2 * km / FIBER_KM_PER_MS;
    add("places", "latency", "Distance and delay (latency)",
      `This server${where ? " in " + where : ""} is about ${fmt(km)} km from you. Even at the speed of light in fibre, a round trip takes at least ${Math.max(1, Math.round(rtt))} ms.`,
      "Real routes are longer than a straight line and pass through many routers, so measured delay is higher. That's why services put servers close to their users.",
      {label: "MDN: Round-trip time (RTT)", url: MDN + "Glossary/Round_Trip_Time"},
      live ? {text: "Measure the real round trip (some servers don't answer pings):", command: `Test-Connection ${ip} -Count 4`} : null);
    if (km >= FAR_KM)
      add("places", "cables", "How data crosses oceans",
        `At ${fmt(km)} km, this connection almost certainly travels through undersea cables.`,
        "Nearly all internet traffic between continents runs through fibre-optic cables on the sea floor, not satellites. A few hundred cables connect the continents.",
        {label: "Submarine Cable Map (TeleGeography)", url: "https://www.submarinecablemap.com/"});
  }
  if (c.provider || (c.lat == null && c.lng == null && c.remote_ip))
    add("places", "anycast", "One address, many places (anycast)",
      `${c.provider || "This service"} uses one address that is served from many locations.`,
      "With anycast, the same IP address is announced from data centres around the world and the network sends you to the nearest one. That's why GeoTracker doesn't pin it to a single spot.",
      {label: "Wikipedia: Anycast", url: WIKI + "Anycast"});
  if (shared)
    add("places", "cdn", "Content delivery networks and data centres",
      `${org} runs data centres in many countries.`,
      "Big providers copy content to servers close to users (a CDN). The server you reach depends on where you are, so the same app can connect to different countries on different days.",
      {label: "MDN: CDN", url: MDN + "Glossary/CDN"});
  if (km != null && !c.city)
    add("places", "geolocation", "How accurate are IP locations?",
      `GeoTracker only knows this server's country${c.country_name ? " (" + c.country_name + ")" : ""}, not its city.`,
      "IP locations come from databases built from registration records and measurements. Country is usually right; city often isn't, and cloud servers may show the company's headquarters rather than the building.",
      {label: "Wikipedia: Internet geolocation", url: WIKI + "Internet_geolocation"});

  // ---- How networks work
  if (port === 443)
    add("network", "tls", "What HTTPS/TLS protects",
      "Port 443 means this connection is encrypted with TLS.",
      "TLS hides the content and checks the server's certificate, but the server's address, rough timing and amount of data are still visible. Encryption shows privacy in transit, not that the destination is trustworthy.",
      {label: "MDN: TLS", url: MDN + "Glossary/TLS"});
  else if (port === 53 || port === 853)
    add("network", "dns", "DNS, the internet's phone book",
      `Port ${port} is used for DNS lookups.`,
      "Before connecting to a website, your computer asks a DNS server to turn the name into an IP address. Whoever runs your DNS server can see which names you look up.",
      {label: "MDN: DNS", url: MDN + "Glossary/DNS"});
  else if (Number.isFinite(port) && port > 0)
    add("network", "ports", "What a port number tells you",
      `This connection uses port ${port}.`,
      "An IP address finds the computer; the port finds the service on it. Well-known ports (80, 443, 53) hint at the service, but any program can use any port.",
      {label: "Wikipedia: List of TCP and UDP port numbers", url: WIKI + "List_of_TCP_and_UDP_port_numbers"});
  if (org)
    add("network", "asn", "Who routes the internet (autonomous systems)",
      `This address belongs to ${org}'s network.`,
      "The internet is tens of thousands of networks (autonomous systems) run by ISPs, clouds and companies. They tell each other which addresses they can reach using a protocol called BGP.",
      {label: "Wikipedia: Autonomous system", url: WIKI + "Autonomous_system_(Internet)"});
  if (live)
    add("network", "traceroute", "See the path your data takes",
      `Your traffic to ${ip} passes through a chain of routers.`,
      "Traceroute lists each router (\"hop\") along the way and how long it took to answer. Large jumps in time often mark long-distance links, such as an ocean crossing.",
      {label: "Microsoft Learn: tracert", url: "https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/tracert"},
      {text: "List the hops (no names, 20 hops max):", command: `tracert -d -h 20 ${ip}`});
  if (ip && ip.includes(":"))
    add("network", "ipv6", "IPv6 addresses",
      "This server uses an IPv6 address.",
      "IPv4 ran out of addresses, so IPv6 uses much longer ones. Your computer may reach some services over IPv6 and others over IPv4.",
      {label: "MDN: IPv6", url: MDN + "Glossary/IPv6"});

  // Keep every security lesson, then fill the rest so all three areas get a turn.
  const security = out.filter(l => l.area === "security");
  const places = out.filter(l => l.area === "places"), network = out.filter(l => l.area === "network");
  const rest = [];
  for (let i = 0; i < Math.max(places.length, network.length); i++) {
    if (places[i]) rest.push(places[i]);
    if (network[i]) rest.push(network[i]);
  }
  return [...security, ...rest].slice(0, Math.max(max, security.length));
}
