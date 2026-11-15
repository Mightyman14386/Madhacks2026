import {useState} from "react";

// "Explore further": insights built by the backend (backend/insights.py) for the selected connection.
// The frontend only renders them. Commands are for the user to copy and run themselves; nothing runs here.
export default function ExploreInsights({items}) {
  const [copied, setCopied] = useState(null);
  const list = (items || []).filter(i => i && typeof i.title === "string");
  if (!list.length) return null;
  const copy = async (id, text) => {
    try { await navigator.clipboard.writeText(text); setCopied(id); setTimeout(() => setCopied(c => c === id ? null : c), 1500); }
    catch { setCopied(null); }
  };
  return <section className="explore-insights" aria-label="Explore this connection further">
    <h4>EXPLORE FURTHER</h4>
    {list.map(i => <div key={i.id} className="insight">
      <strong>{i.title}</strong>
      <p>{i.text}</p>
      {i.command && <div className="insight-command">
        <code>{i.command}</code>
        <button type="button" className="button subtle" onClick={() => copy(i.id, i.command)} aria-label={`Copy command: ${i.title}`}>
          {copied === i.id ? "Copied" : "Copy"}
        </button>
      </div>}
    </div>)}
    {list.some(i => i.command) && <p className="micro">Commands are for you to run in PowerShell; GeoTracker never runs them. They only read information and change nothing.</p>}
  </section>;
}
