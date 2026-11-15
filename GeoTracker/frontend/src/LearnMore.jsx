import {useState} from "react";
import {AREAS, pickLessons} from "./learnTopics";

// "Keep learning": lessons picked for the selected connection, grouped by area. Each opens to show
// the idea, an optional thing to try yourself, and a link to read more.
export default function LearnMore({item, origin}) {
  const [copied, setCopied] = useState(null);
  const lessons = pickLessons(item, origin);
  if (!lessons.length) return null;
  const copy = async (id, text) => {
    try { await navigator.clipboard.writeText(text); setCopied(id); setTimeout(() => setCopied(c => c === id ? null : c), 1500); }
    catch { setCopied(null); }
  };
  return <section className="learn-more" aria-label="Keep learning">
    <h4>KEEP LEARNING</h4>
    {Object.entries(AREAS).map(([area, label]) => {
      const group = lessons.filter(l => l.area === area);
      if (!group.length) return null;
      return <div key={area} className={"learn-area " + area}>
        <div className="learn-area-label">{label}</div>
        {group.map(l => <details key={l.id}>
          <summary><span>{l.title}</span></summary>
          <p className="learn-hook">{l.hook}</p>
          <p>{l.body}</p>
          {l.tryIt && <div className="learn-try">
            <span>Try it: {l.tryIt.text}</span>
            <div className="insight-command"><code>{l.tryIt.command}</code>
              <button type="button" className="button subtle" onClick={() => copy(l.id, l.tryIt.command)} aria-label={`Copy command: ${l.title}`}>{copied === l.id ? "Copied" : "Copy"}</button>
            </div>
          </div>}
          <a className="learn-link" href={l.link.url} target="_blank" rel="noopener noreferrer">Read more: {l.link.label} ↗</a>
        </details>)}
      </div>;
    })}
  </section>;
}
