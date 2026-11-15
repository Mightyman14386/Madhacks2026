import ConnectionExplanation from "./ConnectionExplanation";
import LearningGuide from "./LearningGuide";
import {mergeIncidentSnapshot} from "./incidentSnapshot";
import {useMemo,useState} from "react";
import Globe from "./Globe";
import usePoll from "./usePoll";
import {getIncidents} from "./api";
import {hasCoordinates} from "./data";
import {incidentRoutes,layoutRoutes,severityColor,SEVERITY_COLORS} from "./routeGeometry";
const coordinate=(lat,lng)=>lat.toFixed(3)+", "+lng.toFixed(3);
export default function IncidentView(){
 const [snapshot,setSnapshot]=useState(null),[search,setSearch]=useState(""),[severity,setSeverity]=useState("all"),[selected,setSelected]=useState(null);
 const [rotate,setRotate]=useState(()=>!matchMedia("(prefers-reduced-motion: reduce)").matches);
 const feed=usePoll(getIncidents,3000,true,incoming=>setSnapshot(previous=>mergeIncidentSnapshot(previous,incoming)));
 const allRoutes=useMemo(()=>layoutRoutes(incidentRoutes(snapshot?.incidents||[]).filter(r=>hasCoordinates(r)&&hasCoordinates(r.observedOrigin))),[snapshot]);
 const routes=useMemo(()=>allRoutes.filter(r=>(severity==="all"||r.severity===severity)&&[r.ip,r.description,r.severity].join(" ").toLowerCase().includes(search.toLowerCase())),[allRoutes,severity,search]);
 const chosen=routes.find(r=>r.id===selected),busy=feed.loading||snapshot?.state==="loading";
 const counts=snapshot?.counts||{};
 const issue=feed.error||snapshot?.message;
 const status=issue?(snapshot?.fetched_at?"Showing last successful snapshot":"Connection unavailable"):snapshot?.state==="refreshing"?"Refreshing warehouse snapshot":busy?"Loading warehouse snapshot":"Warehouse snapshot";
 return <div className="incident-view">
  <div className="page-heading"><div><div className="eyebrow"><span/> LEARN THROUGH REPORTED ACTIVITY</div><h1>Understand the journey. <em>Build your awareness.</em></h1><p>Explore where reported activity connects, what the labels mean, and what to look into next.</p></div><span className="incident-source">DATABRICKS / READ ONLY</span></div>
  {issue&&<div className="banner error-banner" role="alert">{issue} {snapshot?.fetched_at?"The previous snapshot remains visible.":"Check the backend connection and Databricks configuration."}</div>}
  {snapshot?.warnings?.map((warning,i)=><div className="banner warning-banner" key={i}>{warning}</div>)}
  <LearningGuide incident item={chosen} stale={!!issue}/>
  <div className="stats-grid">{[
   ["INCIDENTS LOADED",snapshot?.fetched_at?allRoutes.length:"—","Records with known locations"],
   ["HIGH + CRITICAL",snapshot?.fetched_at?(counts.high||0)+(counts.critical||0):"—","Records marked for closer review"],
   ["ROUTES IN VIEW",snapshot?.fetched_at?routes.length:"—","Matches your current filters"],
   ["LAST SUCCESS",snapshot?.fetched_at?new Date(snapshot.fetched_at).toLocaleTimeString([], {hour:"2-digit",minute:"2-digit"}):"—","When these records were last fetched"]
  ].map(([label,value,sub])=><div className="stat" key={label}><div className="stat-label">{label}</div><strong>{value}</strong><span className="stat-sub">{sub}</span></div>)}</div>
  <div className="monitor-grid">
   <section className="globe-panel">
    <div className="panel-heading"><div><div className="eyebrow">SOURCE → DESTINATION</div><h2>Incident routes</h2></div><span className="incident-feed-status" role="status"><i className={"status-dot "+(issue?"amber":busy?"gray":"")}/>{status}</span></div>
    <Globe routes={routes} selected={chosen?.id} onSelect={id=>{setSelected(id);setRotate(false);}} rotate={rotate} setRotate={setRotate}/>
    {!routes.length&&<div className="map-empty"><strong>{busy?"Loading incidents":issue&&!snapshot?.fetched_at?"Waiting for Databricks":allRoutes.length?"No matching incidents":"No incidents returned"}</strong><p>{busy?"The warehouse may need a moment to start.":allRoutes.length?"Adjust the search or severity filter.":"Reported routes will appear here when data is available."}</p></div>}
    <div className="map-footer"><div className="legend">{Object.entries(SEVERITY_COLORS).filter(([key])=>key!=="unknown"||counts.unknown).map(([key,color])=><span key={key}><i style={{background:color}}/>{key[0].toUpperCase()+key.slice(1)}</span>)}</div><span>{Math.min(routes.length,180)} of {routes.length} mapped</span></div>
    <p className="map-note">Points use the table's coordinates. Arcs connect the reported endpoints, not physical network paths. Repeated routes are gently separated; select an incident to highlight it. Up to 180 routes are drawn at once, including your selection.</p>
   </section>
   <aside className="connections-panel">
    <div className="panel-heading"><div><div className="eyebrow">INCIDENT EXPLORER</div><h2>{chosen?"Incident details":"Follow a route"}</h2></div>{chosen&&<button className="icon-button" aria-label="Close incident details" onClick={()=>setSelected(null)}>×</button>}</div>
    {chosen?<div className="connection-detail"><ConnectionExplanation item={chosen}/>
     <div className="detail-tags"><span className="tag" style={{color:severityColor(chosen.severity)}}>{chosen.severity}</span><span className="tag">Reported incident</span></div>
     <dl>{[
      ["Associated IP",chosen.ip||"Not provided"],
      ["Source coordinates",coordinate(chosen.latitude_src,chosen.longitude_src)],
      ["Destination coordinates",coordinate(chosen.latitude_dest,chosen.longitude_dest)],
      ["Description",chosen.description||"No description provided"]
     ].map(([label,value])=><div key={label}><dt>{label}</dt><dd>{value}</dd></div>)}</dl>
     <p className="micro">Locations and severity come from the database. The associated IP is not assumed to identify either endpoint.</p>
    </div>:<>
     <label className="search-box"><input aria-label="Search incidents" placeholder="Search IP, description, severity…" value={search} onChange={e=>{setSearch(e.target.value);setSelected(null);}}/></label>
     <label className="incident-filter">Severity<select aria-label="Incident severity" value={severity} onChange={e=>{setSeverity(e.target.value);setSelected(null);}}><option value="all">All severities</option>{Object.keys(SEVERITY_COLORS).map(key=><option key={key} value={key}>{key[0].toUpperCase()+key.slice(1)}</option>)}</select></label>
     <div className="connection-list">{routes.map(r=><button key={r.id} className="connection-row" onClick={()=>{setSelected(r.id);setRotate(false);}}>
      <span className="process-avatar" style={{color:severityColor(r.severity)}}>↗</span>
      <span className="connection-text"><strong>{r.ip||"Unspecified IP"}</strong><span>{r.description||"No description"}</span><span>{coordinate(r.latitude_src,r.longitude_src)} → {coordinate(r.latitude_dest,r.longitude_dest)}</span></span>
      <span className="incident-severity" style={{color:severityColor(r.severity)}}>{r.severity}</span>
     </button>)}
     {!routes.length&&<div className="empty-list"><strong>{busy?"Fetching incidents…":"No incidents to display"}</strong></div>}
     </div><div className="list-footer"><span>{snapshot?.stale||feed.error?"Last received data":"Database snapshot"}</span><span>{routes.length} INCIDENTS</span></div>
    </>}
   </aside>
  </div>
  <div className="incident-provenance"><span>workspace.default.geospatial_incidents</span><span>Warehouse snapshots refresh every 30 seconds by default</span></div>
 </div>;
}
