import {useState} from "react";
import {restoreQuarantined,deleteQuarantined} from "./api";
import OpNarration from "./OpNarration";

// Quarantine history with Restore / Delete for files still in quarantine.
// Each action asks for confirmation inline; the backend re-checks everything and its message is shown verbatim.
const time=v=>{const d=new Date(v);return Number.isNaN(d.getTime())?"—":d.toLocaleString([], {month:"short",day:"numeric",hour:"2-digit",minute:"2-digit"});};
const COPY={
 restore:{ask:"Move this file back to its original location?",detail:"It will not be started again.",go:"Yes, restore",busy:"Restoring…"},
 delete:{ask:"Permanently delete this file?",detail:"This can't be undone. The record stays in history.",go:"Yes, delete",busy:"Deleting…"},
};

export default function QuarantineList({items,demo,onChanged}) {
 const [pending,setPending]=useState(null); // {id, action} awaiting confirmation
 const [busy,setBusy]=useState(null),[results,setResults]=useState({});

 async function run(id,action){
  setBusy(id);
  try {
   const r=await(action==="restore"?restoreQuarantined(id):deleteQuarantined(id));
   setResults(m=>({...m,[id]:{type:"success",message:r.message}}));onChanged?.();
  } catch(e){setResults(m=>({...m,[id]:{type:"error",message:e.message}}));}
  finally {setBusy(null);setPending(null);}
 }

 return <div className="records">{items.map((q,i)=>{
  const id=q.id??q.manifest_id, actionable=!demo&&q.status==="quarantined"&&!q.is_simulated&&id!=null;
  const asking=pending?.id===id?COPY[pending.action]:null;
  return <div className="record quarantine-record" key={id??i}>
   <div className="quarantine-record-main">
    <strong>{q.process_name||"Process"}</strong>
    <span className={"tag "+(q.status==="quarantined"?"unsafe":"")}>{q.status||"recorded"}</span>
    {q.is_simulated?<span className="tag simulated">Simulated</span>:null}
    <time>{time(q.ts)}</time>
   </div>
   {(q.original_path_redacted||q.sha256_short)&&<div className="micro">{q.original_path_redacted}{q.sha256_short&&<> · sha256 {q.sha256_short}</>}</div>}
   {results[id]&&<div className={"action-result "+results[id].type} role="status">{results[id].message}</div>}
   {id!=null&&<OpNarration match={{manifest_id:id}}/>}
   {actionable&&!asking&&<div className="quarantine-actions">
    <button className="button" disabled={busy===id} onClick={()=>setPending({id,action:"restore"})}>Restore</button>
    <button className="button quarantine-button" disabled={busy===id} onClick={()=>setPending({id,action:"delete"})}>Delete</button>
   </div>}
   {asking&&<div className="geofence-confirm" role="alertdialog" aria-label={asking.ask}>
    <strong>{asking.ask}</strong><p>{asking.detail}</p>
    <div className="dialog-actions">
     <button className="button" disabled={busy===id} onClick={()=>setPending(null)}>Cancel</button>
     <button className={"button "+(pending.action==="delete"?"quarantine-button":"")} disabled={busy===id} onClick={()=>run(id,pending.action)}>{busy===id?asking.busy:asking.go}</button>
    </div>
   </div>}
  </div>;
 })}</div>;
}
