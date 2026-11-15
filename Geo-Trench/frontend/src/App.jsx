import IncidentView from "./IncidentView";
import usePoll from "./usePoll";
import {useEffect,useMemo,useRef,useState} from "react";
import Globe from "./Globe";
import {API_URL,getHealth,getConnections,getAudit,getQuarantine,quarantineConnection} from "./api";
import {hasCoordinates,mergeHistory,makeDemo,routeColor} from "./data";
import "@fontsource/dm-sans/latin-400.css";
import "@fontsource/dm-sans/latin-500.css";
import "@fontsource/dm-sans/latin-600.css";
import "@fontsource/space-grotesk/latin-500.css";
import "./styles.css";

function Icon({name,size=18,...rest}) {
 const paths={globe:<><circle cx="12" cy="12" r="9"/><ellipse cx="12" cy="12" rx="4" ry="9"/><path d="M3 12h18M5 6h14M5 18h14"/></>,activity:<path d="M2 12h4l3-7 5 14 3-7h5"/>,shield:<><path d="m12 3 8 3v6c0 4-4 7-8 9-4-2-8-5-8-9V6z"/><path d="m8 12 3 3 5-6"/></>,search:<><circle cx="10" cy="10" r="6"/><path d="m15 15 5 5"/></>,arrow:<path d="M4 12h16m-6-6 6 6-6 6"/>,lock:<><rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></>,download:<><path d="M12 3v12m-5-5 5 5 5-5M4 16v5h16v-5"/></>,close:<path d="m6 6 12 12M6 18 18 6"/>,clock:<><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></>,refresh:<><path d="M20 8a8 8 0 1 0 0 8M20 3v5h-5"/></>};
 return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" {...rest}>{paths[name]||paths.globe}</svg>;
}
const time=value=>{const date=new Date(value);return Number.isNaN(date.getTime())?"—":date.toLocaleTimeString([], {hour:"2-digit",minute:"2-digit",second:"2-digit"});};
const location=c=>c.country_name || c.country_code || "Location unavailable";

export default function App() {
 const [snapshot,setSnapshot]=useState(null),[history,setHistory]=useState([]),[health,setHealth]=useState(null),[audit,setAudit]=useState([]),[quarantines,setQuarantines]=useState([]);
 const [demo,setDemo]=useState(false),[paused,setPaused]=useState(false),[rotate,setRotate]=useState(()=>!matchMedia("(prefers-reduced-motion: reduce)").matches);
 const [tab,setTab]=useState("overview"),[filter,setFilter]=useState("all"),[search,setSearch]=useState(""),[period,setPeriod]=useState("live"),[selected,setSelected]=useState(null),[updated,setUpdated]=useState(null);
 const [confirm,setConfirm]=useState(false),[busy,setBusy]=useState(false),[action,setAction]=useState(null);
 const [source,setSource]=useState("incidents");
 const deviceVisible=source==="device"||tab!=="overview";
 const dialog=useRef(null), searchInput=useRef(null);
 useEffect(()=>{const onKey=e=>{if(e.key==="/" && !["INPUT","TEXTAREA","SELECT"].includes(document.activeElement?.tagName) && !document.activeElement?.isContentEditable){e.preventDefault();searchInput.current?.focus();}};window.addEventListener("keydown",onKey);return()=>window.removeEventListener("keydown",onKey);},[]);
 const feed=usePoll(getConnections,2500,!demo&&!paused&&deviceVisible,data=>{setSnapshot(data);setHistory(old=>mergeHistory(old,data));setUpdated(new Date());});
 const healthFeed=usePoll(getHealth,30000,!demo||!deviceVisible,data=>setHealth(data));
 const auditFeed=usePoll(getAudit,4500,!demo&&!paused&&deviceVisible,data=>setAudit(Array.isArray(data)?data:[]));
 const quarantineFeed=usePoll(getQuarantine,5000,!demo&&tab==="quarantine",data=>setQuarantines(data.items||[]));
 useEffect(()=>{if(confirm){dialog.current?.showModal();}else dialog.current?.close();},[confirm]);
 const demoSnapshot=useMemo(()=>makeDemo(),[]);
 const data=demo?demoSnapshot:snapshot;
 const rows=useMemo(()=> {
  const source=period==="recent"&&!demo?history:data?.connections||[];
  return source.filter(c=>(filter==="all"||c.status===filter) && [c.process_name,c.country_name,c.country_code,c.remote_ip,c.asn_org].filter(Boolean).join(" ").toLowerCase().includes(search.toLowerCase()));
 },[data,period,history,demo,filter,search]);
 const selectedConnection=rows.find(c=>c.id===selected) || (data?.anycast||[]).find(c=>c.id===selected);
 const routes=rows.filter(c=>hasCoordinates(c)&&hasCoordinates(c.observedOrigin||data?.origin));
 const stats=data?.stats||{},countries=new Set((data?.connections||[]).map(c=>c.country_code).filter(Boolean));
 const unlocated=rows.length-routes.length;
 const mode=demo?"Preview only":health?health.enforcement_enabled?"Enforcing":"Dry-run":"Unconfirmed";
 const events=demo?demoSnapshot.connections.filter(c=>c.status==="unsafe").map(c=>({ts:c.first_seen,type:"demo_finding",severity:c.severity,message:c.process_name+" · synthetic connection to "+c.country_name,ref_id:c.id})):audit;
 function switchDemo(value){setDemo(value);setSelected(null);setAction(null);setConfirm(false);if(value)setPaused(false);}
 async function quarantine(){
  if(!selectedConnection || demo)return;
  setBusy(true);setAction(null);
  try {const r=await quarantineConnection(selectedConnection.id);setAction({type:"success",message:r.simulated?"Simulated quarantine completed. No real files were moved.":r.message||"The backend completed the quarantine request."});}
  catch(e){setAction({type:"error",message:e.status===403?"Safety Override: this process is protected. The backend refused quarantine.":e.status===409?"Process changed or another quarantine is running. Refresh the connection and try again.":e.status===422?"The backend rejected the request. No action was taken.":e.message});}
  finally {setBusy(false);setConfirm(false);}
 }
 function exportSnapshot(){
  const blob=new Blob([JSON.stringify({exported_at:new Date().toISOString(),mode:demo?"synthetic-preview":"observed",origin:data?.origin,connections:rows.map(({exe,ancestry_detail,...c})=>c)},null,2)],{type:"application/json"});
  const url=URL.createObjectURL(blob),a=document.createElement("a");a.href=url;a.download="geotrench-connections.json";a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
 }
 return <div className="app-shell">
  <aside className="rail"><a href="#" className="brand-symbol" aria-label="Geo-Trench overview" onClick={()=>setTab("overview")}><span/><span/><span/></a><div className="rail-line"/>{[["overview","globe","Overview"],["activity","activity","Activity"],["quarantine","shield","Quarantine"]].map(([id,icon,label])=><button key={id} className={tab===id?"rail-button selected":"rail-button"} aria-label={label} title={label} onClick={()=>setTab(id)}><Icon name={icon}/></button>)}<div className="rail-bottom"><span className="local-indicator"/><span>LOCAL</span></div></aside>
  <div className="workspace">
   <header className="topbar"><a className="wordmark" href="#" onClick={()=>setTab("overview")}>GEO<span>—</span>TRENCH<span className="version"> / 01</span></a><nav>{["overview","activity","quarantine"].map(id=><button key={id} onClick={()=>setTab(id)} className={tab===id?"nav-active":""}>{id[0].toUpperCase()+id.slice(1)}</button>)}</nav><div className="backend-status"><span className={"status-dot "+(demo?"amber":healthFeed.error||(deviceVisible&&feed.error)?"red":health?"":"gray")}/>{demo&&deviceVisible?"DEMO ENVIRONMENT":healthFeed.error||feed.error?"BACKEND OFFLINE":health?"BACKEND CONNECTED":"CONNECTING"}</div></header>
   <main>
    {tab==="overview"&&<div className="source-switch segmented" aria-label="Data source">{[["incidents","Databricks incidents"],["device","Device traffic"]].map(([id,label])=><button key={id} className={source===id?"chosen":""} aria-pressed={source===id} onClick={()=>{setSource(id);switchDemo(false);}}>{label}</button>)}</div>}
    {!deviceVisible?<IncidentView/>:<>
    <div className="page-heading"><div><div className="eyebrow"><span/> NETWORK INTELLIGENCE</div><h1>Your network. <em>In perspective.</em></h1><p>Follow the connections. Understand what crosses your boundaries.</p></div><div className="heading-actions"><button className="button subtle" onClick={()=>switchDemo(!demo)}>{demo?"Return to live":"Explore demo"} <Icon name="arrow" size={15}/></button><button className="button" onClick={exportSnapshot} disabled={!data}><Icon name="download" size={15}/> Export view</button></div></div>
    {demo&&<div className="banner demo-banner"><span>SYNTHETIC PREVIEW</span> Example routes only. Not your device traffic. Security actions are disabled.</div>}
    {!demo&&(feed.error||healthFeed.error)&&<div className="banner error-banner"><Icon name="activity"/> Backend unavailable at {API_URL}. {feed.error||healthFeed.error} {snapshot?"Showing the last received snapshot.":"Start the backend or explore the synthetic demo."}</div>}
    {data?.warnings?.map((warning,i)=><div className="banner warning-banner" key={i}>{typeof warning==="string"?warning:JSON.stringify(warning)}</div>)}
    {data?.truncated&&<div className="banner warning-banner">The backend truncated this snapshot. Counts and visible routes may differ.</div>}
    <div className="stats-grid">{[
     ["CONNECTIONS",stats.total,"Observed in the latest check","globe"],
     ["REGIONS REACHED",data?countries.size:undefined,"Approximate country locations","arrow"],
     ["NEEDS ATTENTION",stats.unsafe,"Flagged by the backend","shield"],
     ["PROTECTION MODE",mode,demo?"No actions are executed":health?.is_admin?"Administrator access":health?"Standard privileges":"Waiting for health check","lock"]
    ].map(([label,value,sub,icon],i)=><div className={"stat "+(i===2&&stats.unsafe?"stat-alert":"")} key={label}><div className="stat-label">{label}<Icon name={icon} size={15}/></div><strong className={typeof value==="string"?"text-value":""}>{value??"—"}{i===2&&stats.unsafe>0&&<span className="tiny-pill">REVIEW</span>}</strong><span className="stat-sub">{sub}</span></div>)}</div>
    {tab==="overview"&&<div className="monitor-grid"><section className="globe-panel">
      <div className="panel-heading"><div><div className="eyebrow">GLOBAL CONNECTION MAP</div><h2>A world of connections</h2></div><div className="segmented" aria-label="Connection time range"><button className={period==="live"?"chosen":""} onClick={()=>setPeriod("live")}>Latest check</button><button className={period==="recent"?"chosen":""} onClick={()=>setPeriod("recent")}>Session · 15m</button></div></div>
      <div className="map-meta"><span><i className="status-dot"/>{data?.origin?.name||"Origin not available"} <span className="muted">/ YOUR DEVICE</span></span><span className="mono">{demo?"SYNTHETIC":data?.geoip_fallback?"GEOIP FALLBACK":"APPROXIMATE GEOIP"}</span></div>
      <Globe routes={routes} origin={data?.origin} selected={selected} onSelect={id=>{setSelected(id);setAction(null);}} rotate={rotate} setRotate={setRotate}/>
      {!data&&<div className="map-empty"><strong>{feed.loading?"Listening for your first snapshot":"Your network view starts here"}</strong><p>Connect the backend to see real routes,<br/>or explore a clearly labeled demo.</p><button className="button" onClick={()=>switchDemo(true)}>Explore demo <Icon name="arrow" size={14}/></button></div>}
      <div className="map-footer"><div className="legend"><span><i style={{background:"#91cbc0"}}/>Safe</span><span><i style={{background:"#e2c28b"}}/>Medium finding</span><span><i style={{background:"#e7a1ad"}}/>High / critical</span></div><span>{routes.length>180?"180 of "+routes.length:routes.length} mapped · {unlocated} unlocated</span></div>
      <p className="map-note">Routes connect your device to approximate remote locations; they do not establish traffic direction or a physical network path. Session history is retained in memory only.</p>
    </section>
    <aside className="connections-panel"><div className="panel-heading"><div><div className="eyebrow">ENDPOINT EXPLORER</div><h2>{selectedConnection?"Connection details":"Beyond your device"}</h2></div>{selectedConnection&&<button className="icon-button" aria-label="Close connection details" onClick={()=>{setSelected(null);setAction(null);}}><Icon name="close"/></button>}</div>
     {selectedConnection?<div className="connection-detail"><div className="detail-heading"><span className="process-avatar" style={{color:routeColor(selectedConnection)}}><Icon name="globe"/></span><div><h3>{selectedConnection.process_name}</h3><span className="mono">{selectedConnection.id}</span></div></div><div className="detail-tags"><span className={"tag "+selectedConnection.status}>{selectedConnection.status||"unknown"}</span><span className="tag">{selectedConnection.severity||"unrated"}</span>{selectedConnection.is_simulated&&<span className="tag simulated">Simulated</span>}{selectedConnection.is_protected&&<span className="tag"><Icon name="lock" size={11}/> Protected</span>}</div>
      <dl>{[["Location",location(selectedConnection)],["Provider",selectedConnection.asn_org||selectedConnection.provider||"Unknown"],["Remote endpoint",selectedConnection.remote_ip+":"+selectedConnection.remote_port],["First seen",time(selectedConnection.first_seen)],["Process ancestry",(selectedConnection.ancestry||[]).join(" → ")||"Unavailable"]].map(([k,v])=><div key={k}><dt>{k}</dt><dd>{v}</dd></div>)}</dl>
      <h4>BACKEND FINDINGS</h4>{selectedConnection.reasons?.length?<ul className="reasons">{selectedConnection.reasons.map((r,i)=><li key={i}>{r}</li>)}</ul>:<p className="muted">No reasons were returned for this connection.</p>}
      {!!selectedConnection.rules_fired?.length&&<div className="rule-tags">{selectedConnection.rules_fired.map(r=><span className="tag" key={r}>{r}</span>)}</div>}
      {action&&<div className={"action-result "+action.type} role="status">{action.message}</div>}
      <button className="button quarantine-button" disabled={demo||busy||period==="recent"} onClick={()=>setConfirm(true)}><Icon name={selectedConnection.is_protected?"lock":"shield"} size={15}/>{demo?"Preview — actions disabled":period==="recent"?"Select latest check to act":"Request quarantine"}</button><p className="micro">The backend re-checks protection and process identity. {selectedConnection.is_protected?"Protected processes can be refused with a Safety Override.":""}</p>
     </div>:<>
      <label className="search-box"><Icon name="search" size={16}/><input ref={searchInput} value={search} onChange={e=>setSearch(e.target.value)} placeholder="Search process, region, IP…" aria-label="Search connections"/><kbd>/</kbd></label>
      <div className="filter-row">{[["all","All"],["unsafe","Attention"],["safe","Safe"]].map(([id,label])=><button key={id} className={filter===id?"filter-active":""} onClick={()=>setFilter(id)}>{label}{id==="all"&&<span>{rows.length}</span>}</button>)}</div>
      <div className="connection-list">{rows.length?rows.map(c=><button className="connection-row" key={c.id} onClick={()=>{setSelected(c.id);setRotate(false);setAction(null);}}><span className="process-avatar" style={{color:routeColor(c)}}><Icon name={c.is_protected?"lock":"globe"} size={16}/></span><span className="connection-text"><strong>{c.process_name}</strong><span>{location(c)} <b>·</b> {c.asn_org||"Unknown provider"}</span></span><span className="connection-trailing"><i style={{background:routeColor(c)}}/>{c.is_simulated&&<small>DEMO</small>}<Icon name="arrow" size={14}/></span></button>):<div className="empty-list"><Icon name="globe" size={28}/><strong>{data?"No matching connections":"Waiting for connections"}</strong><p>{data?"Try another filter or search.":"Your observed endpoints will appear here."}</p></div>}</div>
      <div className="list-footer"><span>{period==="recent"?"Observed this session":"Latest snapshot"}</span><span className="mono">{rows.length} ENDPOINTS</span></div>
     </>}
    </aside></div>}
    {tab==="quarantine"&&<section className="standalone panel"><div className="panel-heading"><div><div className="eyebrow">BACKEND RECORDS</div><h2>Quarantine history</h2></div><Icon name="shield"/></div>{demo?<div className="empty-list"><Icon name="shield" size={32}/><h3>No actions in preview mode</h3><p>Return to live monitoring to view backend records.</p></div>:quarantineFeed.error?<div className="banner warning-banner">Quarantine history unavailable: {quarantineFeed.error}</div>:quarantineFeed.loading?<p className="muted">Loading records…</p>:quarantines.length?<div className="records">{quarantines.map((q,i)=><div className="record" key={q.manifest_id||q.id||i}><strong>{q.process_name||"Process"}</strong><span className="tag">{q.status||"recorded"}</span><time>{time(q.ts)}</time></div>)}</div>:<div className="empty-list"><Icon name="shield" size={32}/><h3>No quarantine records</h3><p>Actions appear here only after the backend records them.</p></div>}<p className="micro">Restoration and region-blocking controls will become available when supported by the backend.</p></section>}
    {(tab==="overview"||tab==="activity")&&<section className="activity-panel"><div className="panel-heading"><div className="activity-title"><Icon name="activity" size={18}/><h2>Activity stream</h2><span className="count-tag">{events.length}</span></div><button className="live-toggle" disabled={demo} onClick={()=>setPaused(!paused)}><span className={"status-dot "+(paused?"gray":"")}/>{demo?"SYNTHETIC EVENTS":paused?"RESUME UPDATES":"LIVE UPDATES"} <span>{paused?"▶":"Ⅱ"}</span></button></div>{!demo&&auditFeed.error&&<p className="inline-error">Activity unavailable: {auditFeed.error}</p>}<div className={tab==="overview"?"event-list compact":"event-list"}>{events.length?events.map((event,i)=><button key={event.ts+"-"+event.type+"-"+event.ref_id+"-"+i} className="event-row" onClick={()=>{if(data?.connections?.some(c=>c.id===event.ref_id)){setSource("device");setTab("overview");setSelected(event.ref_id);setPeriod("live");setFilter("all");setSearch("");}}}><time>{time(event.ts)}</time><span className={"event-tag "+event.severity}>{event.type.replaceAll("_"," ")}</span><span>{event.message}</span><Icon name="arrow" size={14}/></button>):<div className="activity-empty">No events received. New backend findings will appear here.</div>}</div></section>}
    <div className="bottom-grid"><section className="anycast panel"><div className="panel-heading"><div><div className="eyebrow">DISTRIBUTED INFRASTRUCTURE</div><h2>Beyond a single location <span className="count-tag">{data?.anycast?.length||0}</span></h2></div><Icon name="globe"/></div><p className="muted">Anycast endpoints are served from multiple places. We keep them off the map rather than assign a misleading location.</p><div className="anycast-list">{data?.anycast?.length?data.anycast.map(c=><button key={c.id} className="anycast-row" onClick={()=>{setSource("device");setTab("overview");setSelected(c.id);}}><span className="status-dot" style={{background:routeColor(c)}}/><strong>{c.provider||c.asn_org||c.process_name}</strong><code>{c.remote_ip}</code>{c.is_simulated&&<span className="tag">Demo</span>}<Icon name="arrow" size={14}/></button>):<p className="micro">No distributed endpoints reported.</p>}</div></section><section className="coverage panel"><div className="eyebrow">VISIBILITY & CONTEXT</div><h2>Clarity over certainty.</h2><p>IP locations are approximate. Cloud services may appear in a different region from the physical server.</p><dl><div><dt>Geolocation</dt><dd>{!data?"Waiting":data.geoip_fallback?"Fallback dataset":"GeoIP dataset"}</dd></div><div><dt>Blocked regions</dt><dd>{stats.blocked_regions?.join(", ")||"None reported"}</dd></div><div><dt>Hidden by geofence</dt><dd>{stats.hidden_by_geofence??"—"}</dd></div></dl></section></div>
   </>}
   </main>
   <footer className="app-footer"><span><i className="status-dot"/> {deviceVisible?"LOCAL OBSERVATION. GLOBAL PERSPECTIVE.":"REPORTED INCIDENTS. GLOBAL PERSPECTIVE."}</span><span>{!deviceVisible?"Databricks incident feed":demo?"Synthetic preview":updated?"Last check "+time(updated):"Awaiting first check"} <b>·</b> {!deviceVisible?"Read only":data?.generated_ms!=null?data.generated_ms+" ms":"—"}</span><span>GEO—TRENCH © {new Date().getFullYear()}</span></footer>
  </div>
  <dialog ref={dialog} onCancel={()=>setConfirm(false)} onClose={()=>setConfirm(false)} className="confirm-dialog"><div className="dialog-icon"><Icon name="shield" size={24}/></div><h2>Request quarantine?</h2><p>This sends the connection ID for <strong>{selectedConnection?.process_name}</strong> to the backend. The server decides whether an action is permitted.</p><div className="banner warning-banner">{selectedConnection?.is_simulated?"This connection is simulated; quarantine is a dry run.":health?.enforcement_enabled?"Enforcement is active. This action may affect a real process or file.":"Health indicates dry-run or unconfirmed mode. The backend determines the actual result."}</div><div className="dialog-actions"><button className="button" disabled={busy} onClick={()=>setConfirm(false)}>Cancel</button><button className="button quarantine-button" disabled={busy||demo||!selectedConnection} onClick={quarantine}>{busy?"Requesting…":"Confirm request"}</button></div></dialog>
 </div>;
}
