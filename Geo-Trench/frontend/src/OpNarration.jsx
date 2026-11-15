import {useEffect,useRef} from "react";
import {useLatestOp} from "./liveOps";
import {STEP_WHY,KIND_LABEL} from "./lessons";

// Step-by-step narration of the latest action on this item, with a one-line "why" per step.
// Step messages come from the backend verbatim; the "why" lines are local teaching text.
export default function OpNarration({match}) {
  const op = useLatestOp(match);
  const box = useRef(null);
  // Bring a newly started action into view inside its scrolling panel.
  useEffect(() => { if (op?.op_id) box.current?.scrollIntoView({block: "nearest", behavior: "smooth"}); }, [op?.op_id]);
  if (!op) return null;
  const order = [], latest = {};
  for (const ev of op.events) {
    if (ev.type !== "op_step" || !ev.step) continue;
    if (!(ev.step in latest)) order.push(ev.step);
    latest[ev.step] = ev;
  }
  const end = op.ended;
  const icon = s => s === "ok" ? "✓" : s === "failed" ? "✕" : "…";
  return <section ref={box} className="op-narration" aria-live="polite" aria-label="What Geo-Trench is doing">
    <div className="op-head">
      <span>{end ? "WHAT GEO-TRENCH DID" : "WHAT GEO-TRENCH IS DOING"}</span>
      <strong>{KIND_LABEL[op.kind] || op.kind}</strong>
      {op.is_simulated && <span className="tag simulated">Simulated</span>}
      {end?.elapsed_ms != null && <span className="op-time">{Math.round(end.elapsed_ms)} ms</span>}
    </div>
    <ol>
      {order.map(step => {
        const ev = latest[step];
        return <li key={step} className={"op-step " + ev.status}>
          <span className="op-icon" aria-hidden="true">{icon(ev.status)}</span>
          <div>
            <strong>{step[0].toUpperCase() + step.slice(1)}</strong>
            {ev.message && <span className="op-message">{ev.message}</span>}
            {STEP_WHY[`${op.kind}:${step}`] && <p>{STEP_WHY[`${op.kind}:${step}`]}</p>}
          </div>
        </li>;
      })}
    </ol>
    {end && <div className={"op-end " + end.status}>{end.message}</div>}
  </section>;
}
