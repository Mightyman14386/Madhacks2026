import {useEffect,useMemo,useState} from "react";
import {previewGeofence,geofenceCountry,undoGeofence,getGeofenceState} from "./api";
import OpNarration from "./OpNarration";

// Side panel for a country picked on the device globe: backend preview -> inline confirm -> geofence.
// Every number, note and message comes from the backend and is shown verbatim; the explanations
// teach what a geofence can and can't do.
const mmss=s=>s==null?"—":`${Math.floor(s/60)}:${String(s%60).padStart(2,"0")}`;

export default function GeofencePanel({country,demo,connections,onClose,onChanged}) {
 const [preview,setPreview]=useState(null),[loading,setLoading]=useState(false),[error,setError]=useState(null);
 const [confirming,setConfirming]=useState(false),[busy,setBusy]=useState(false),[result,setResult]=useState(null);
 const [region,setRegion]=useState(null); // this country's entry from /api/geofence/state while geofenced
 const [reload,setReload]=useState(0);

 useEffect(()=>{
  setPreview(null);setError(null);setConfirming(false);
  if(!country?.code||demo)return;
  const controller=new AbortController();setLoading(true);
  previewGeofence(country.code,controller.signal)
   .then(p=>setPreview(p))
   .catch(e=>{if(e.name!=="AbortError")setError(e.message);})
   .finally(()=>setLoading(false));
  return()=>controller.abort();
 },[country?.code,demo,reload]);
 useEffect(()=>{setResult(null);setRegion(null);},[country?.code]);

 const blocked=!!preview?.already_blocked;
 // While geofenced: poll the backend state for blocked servers and the countdown.
 useEffect(()=>{
  if(!blocked||!country?.code)return;
  let stop=false,timer;const controller=new AbortController();
  const tick=()=>getGeofenceState(controller.signal)
   .then(s=>{if(!stop)setRegion((s.blocked||[]).find(b=>b.country_code===country.code)||null);})
   .catch(()=>{})
   .finally(()=>{if(!stop)timer=setTimeout(tick,5000);});
  tick();
  return()=>{stop=true;controller.abort();clearTimeout(timer);};
 },[blocked,country?.code,reload]);

 // "Why a site may still load": the same apps' connections to OTHER countries keep working.
 const stillReachable=useMemo(()=>{
  const procs=new Set((region?.blocked_ips||[]).map(b=>b.process).filter(Boolean));
  if(!procs.size)return [];
  const byProc={};
  for(const c of connections||[]){
   if(!procs.has(c.process_name)||c.country_code===country.code)continue;
   const m=(byProc[c.process_name]??={});const where=c.country_name||c.country_code||"Unknown";m[where]=(m[where]||0)+1;
  }
  return Object.entries(byProc).map(([proc,m])=>[proc,Object.entries(m).sort((a,b)=>b[1]-a[1])]);
 },[region,connections,country.code]);

 async function run(action){
  setBusy(true);setResult(null);
  try {
   const r=await(action==="block"?geofenceCountry(country.code):undoGeofence(country.code));
   setResult({type:"success",message:r.message});
   onChanged?.();
  } catch(e){setResult({type:"error",message:e.message});}
  finally {setBusy(false);setConfirming(false);setReload(n=>n+1);}
 }

 const enforced=preview?.mode==="enforced";
 const name=country.name;
 return <div className="connection-detail geofence-panel">
  <div className="panel-heading"><div><div className="eyebrow">GEOFENCE REGION</div><h2>{name}{country.code&&<span className="mono muted"> · {country.code}</span>}</h2></div>
   <button className="icon-button" aria-label="Close geofence panel" onClick={onClose}>×</button></div>

  {!country.code?<div className="banner warning-banner">This region has no ISO country code, so it can't be geofenced.</div>
  :demo?<div className="banner warning-banner">Explore demo is on. Return to live monitoring to geofence a region.</div>
  :<>
   {loading&&<p className="muted">Loading preview from the backend…</p>}
   {error&&<div className="banner error-banner">{error}</div>}
   {preview&&<>
    <div className="detail-tags">
     <span className={"tag "+(enforced?"unsafe":"")}>{enforced?"Enforced":"Dry run"}</span>
     {blocked&&<span className="tag unsafe">Geofenced</span>}
    </div>
    <p className="micro">{preview.mode_reason}</p>

    {!blocked&&<div className="geofence-learn">
     <strong>How a geofence works</strong>
     <p>Geo-Trench blocks the <b>servers located in {name}</b> that your apps have talked to, right now or in the last 15 minutes, and keeps adding new ones within seconds as they appear.</p>
     <p>It blocks <b>servers by location, not websites by country</b>. A “.in” or “.cn” site can still load if its pages come from servers somewhere else, like a CDN in the US or Hong Kong.</p>
    </div>}

    <dl>{[
     [blocked?"Servers blocked":"Servers to block now",blocked&&region?region.ip_count:preview.ip_count],
     blocked&&region?["Expires in",mmss(region.seconds_remaining)]:["Seen in last 15 min",preview.recent_ip_count??0],
     ["Your connections affected",preview.real_connections_affected],
     ["Auto-expires after",preview.ttl_minutes+" min"],
    ].map(([k,v])=><div key={k}><dt>{k}</dt><dd>{v??"—"}</dd></div>)}</dl>

    {!blocked&&!!preview.ips?.length&&<><h4>SERVERS THAT WILL BE BLOCKED</h4><div className="geofence-ips">{preview.ips.slice(0,12).map(ip=><code key={ip}>{ip}</code>)}{preview.ips.length>12&&<span className="micro">+{preview.ips.length-12} more</span>}</div></>}
    {!blocked&&!!preview.notes?.length&&<ul className="reasons">{preview.notes.map((n,i)=><li key={i}>{n}</li>)}</ul>}
    {!blocked&&preview.command_display&&<pre className="geofence-command">{preview.command_display}</pre>}

    {blocked&&<>
     <h4>BLOCKED SERVERS IN {name.toUpperCase()}</h4>
     {region?.blocked_ips?.length?<div className="geofence-blocked">{region.blocked_ips.map(b=><div key={b.ip}>
      <code>{b.ip}</code><span>{[b.city,b.asn_org].filter(Boolean).join(" · ")||"Location detail unavailable"}</span>{b.process&&<small>used by {b.process}</small>}
     </div>)}</div>:<p className="micro">No servers in {name} yet. New ones are blocked within seconds of first contact.</p>}

     <div className="geofence-learn">
      <strong>Why a website might still load</strong>
      {stillReachable.length?stillReachable.map(([proc,places])=><p key={proc}><b>{proc}</b> is still reaching {places.map(([where,n])=>`${where} (${n})`).join(", ")}. Those servers aren't in {name}, so they keep working, and they may be serving most of the page.</p>)
       :<p>Pages are built from many servers. Only the ones located in {name} are blocked; anything served from other countries (often a CDN) still loads.</p>}
      <p>The first request to a brand-new {name} server can get through before it's blocked; reload after a few seconds.</p>
     </div>
     <div className="geofence-tip"><strong>See it yourself</strong> In Chrome press F12 → Network, tick “Disable cache”, and reload. Requests to the blocked servers fail; the rest load.</div>
    </>}
   </>}

   {result&&<div className={"action-result "+result.type} role="status">{result.message}</div>}
   <OpNarration match={{country_code:country.code}}/>

   {preview&&!confirming&&(blocked
    ?<button className="button" disabled={busy} onClick={()=>run("undo")}>{busy?"Removing…":"Remove geofence"}</button>
    :<button className="button quarantine-button" disabled={busy} onClick={()=>setConfirming(true)}>Geofence {name}</button>)}

   {confirming&&<div className="geofence-confirm" role="alertdialog" aria-label={"Confirm geofence for "+name}>
    <strong>Block outbound traffic to {name}?</strong>
    <p>{enforced
     ?`A real Windows Firewall rule will block ${preview.ip_count} server(s) now; new ${name} servers are added as they appear.`
     :"Dry run: the backend records the geofence and hides these connections, but sends no firewall rule."}</p>
    <div className="dialog-actions">
     <button className="button" disabled={busy} onClick={()=>setConfirming(false)}>Cancel</button>
     <button className="button quarantine-button" disabled={busy} onClick={()=>run("block")}>{busy?"Geofencing…":"Yes, geofence"}</button>
    </div>
   </div>}
   <p className="micro">The backend decides what is blocked and never blocks your gateway or DNS servers. Rules are removed on undo, on expiry, and when the backend stops.</p>
  </>}
 </div>;
}
