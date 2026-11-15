import {createContext,useContext,useEffect,useMemo,useState} from "react";
import {API_URL} from "./api";

// Live operation steps from the backend event stream (/api/events/stream), kept in memory for this page.
// EventSource reconnects by itself and resumes with Last-Event-ID.
const MAX_OPS = 60;
const Ctx = createContext({ops: {}});

export function LiveOpsProvider({enabled = true, children}) {
  const [ops, setOps] = useState({});
  useEffect(() => {
    if (!enabled || typeof EventSource === "undefined") return;
    const es = new EventSource(API_URL + "/api/events/stream");
    const onEvent = e => {
      let ev; try { ev = JSON.parse(e.data); } catch { return; }
      if (!ev?.op_id) return;
      setOps(prev => {
        const cur = prev[ev.op_id] || {op_id: ev.op_id, kind: ev.kind, target: ev.target || {}, first_id: ev.id, events: []};
        const next = {...prev, [ev.op_id]: {...cur, is_simulated: ev.is_simulated, events: [...cur.events, ev],
          ended: ev.type === "op_end" ? ev : cur.ended}};
        const keys = Object.keys(next);
        if (keys.length > MAX_OPS) keys.sort((a, b) => next[a].first_id - next[b].first_id).slice(0, keys.length - MAX_OPS).forEach(k => delete next[k]);
        return next;
      });
    };
    for (const type of ["op_start", "op_step", "op_end"]) es.addEventListener(type, onEvent);
    return () => es.close();
  }, [enabled]);
  return <Ctx.Provider value={{ops}}>{children}</Ctx.Provider>;
}

// Newest op whose target matches every given key (conn_id / country_code / manifest_id).
export function useLatestOp(match) {
  const {ops} = useContext(Ctx);
  const key = JSON.stringify(match);
  return useMemo(() => {
    const want = Object.entries(match).filter(([, v]) => v != null);
    if (!want.length) return null;
    let best = null;
    for (const op of Object.values(ops)) {
      if (want.every(([k, v]) => op.target?.[k] === v) && (!best || op.first_id > best.first_id)) best = op;
    }
    return best;
  }, [ops, key]); // eslint-disable-line react-hooks/exhaustive-deps
}
