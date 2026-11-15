import {RULE_LESSONS,SHELLS} from "./lessons";

// "Checks GeoTracker ran" for ANY selected connection, safe or flagged.
// Pass/flag comes only from the backend's rules_fired; the frontend adds the explanation from the
// connection's own data (port, how it started, where it runs). Each check expands into its lesson.
const ORDER = ["suspicious_port", "office_spawn", "shell_spawn", "risky_location"];
const WELL_KNOWN_PORTS = {443: "the standard port for encrypted web traffic (HTTPS)", 80: "the standard port for plain web traffic (HTTP)",
  53: "the port for DNS lookups", 993: "the port for encrypted email (IMAP)", 5228: "the port Google uses for app notifications"};
const RISKY_FOLDER = /\\(temp|downloads)\\|^[a-z]:\\users\\public\\/i;

function passReason(id, item) {
  const chain = (item.ancestry || []).filter(n => typeof n === "string");
  const above = chain.slice(0, -1).map(n => n.toLowerCase());
  const port = item.remote_port;
  switch (id) {
    case "suspicious_port":
      return `Port ${port ?? "unknown"} isn't on the watch list.` + (WELL_KNOWN_PORTS[port] ? ` ${port} is ${WELL_KNOWN_PORTS[port]}.` : "");
    case "office_spawn":
      return "No Office app (Word, Excel, PowerPoint, Outlook) appears earlier in how this app started.";
    case "shell_spawn": {
      const shell = [...above].reverse().find(n => SHELLS.has(n));
      return shell
        ? `${shell} appears earlier in how this app started, but on its own that's common (terminals, installers, dev tools), so it isn't flagged unless something else looks unusual.`
        : "No command shell or script host appears earlier in how this app started.";
    }
    case "risky_location":
      if (!item.exe) return "GeoTracker couldn't read where this program runs from.";
      return RISKY_FOLDER.test(item.exe) ? "It runs from a folder GeoTracker watches, but the backend didn't count it here."
        : "It doesn't run from a Temp, Downloads or shared Public folder.";
    default: return "";
  }
}

export default function RuleLessons({item}) {
  if (!item) return null;
  const fired = new Set(item.rules_fired || []);
  return <section className="rule-lessons" aria-label="Checks GeoTracker ran">
    <h4>CHECKS GeoTracker RAN</h4>
    {ORDER.map(id => {
      const l = RULE_LESSONS[id], hit = fired.has(id);
      return <details key={id} className={hit ? "flagged" : "passed"} open={hit && id === ORDER.find(r => fired.has(r))}>
        <summary>
          <span className="check-mark" aria-hidden="true">{hit ? "⚑" : "✓"}</span>
          <span>{l.title}</span>
          <em>{hit ? "Flagged" : "Passed"}</em>
        </summary>
        <p className="check-reason">{hit ? l.checks : passReason(id, item)}</p>
        <dl>
          {!hit && <div><dt>What it checks</dt><dd>{l.checks}</dd></div>}
          <div><dt>Why it matters</dt><dd>{l.why}</dd></div>
          <div><dt>Harmless lookalike</dt><dd>{l.lookalike}</dd></div>
          {hit && <div><dt>What to check next</dt><dd>{l.next}</dd></div>}
        </dl>
      </details>;
    })}
    {item.is_protected && <div className="protected-note"><strong>🔒 Protected app</strong> It runs from a Windows or Program Files folder, or is a core Windows process. GeoTracker will refuse to quarantine it, because stopping or moving it could break your computer.</div>}
    {[...fired].some(r => !RULE_LESSONS[r]) && <p className="micro">Other findings: {[...fired].filter(r => !RULE_LESSONS[r]).join(", ")}</p>}
    <p className="micro">{fired.size ? "A finding is a reason to look closer, not proof of an attack." : "Passing every check doesn't prove an app is trustworthy. It means nothing matched these common warning signs."}</p>
  </section>;
}
