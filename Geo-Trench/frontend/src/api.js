import {validateIncidentSnapshot} from "./incidentSnapshot.js";
// Backend owns every security decision. Actions send stable IDs only.
export const API_URL = import.meta.env.VITE_API_URL || "http://127.0.0.1:8000";
export class ApiError extends Error {
  constructor(message, status, code) { super(message); this.status=status; this.code=code; }
}
async function request(path, {signal, ...options}={}) {
  const controller=new AbortController();
  const abort=()=>controller.abort(); signal?.addEventListener("abort",abort,{once:true});
  if(signal?.aborted)controller.abort();
  const timer=setTimeout(abort,12000);
  try {
    const res=await fetch(API_URL+path,{...options,signal:controller.signal,headers:{"Content-Type":"application/json",...options.headers}});
    let body;try {body=await res.json();}catch {body=null;}
    if(!res.ok || body?.ok===false) {
      const detail=body?.detail || body;
      const message=typeof detail==="string"?detail:detail?.message;
      throw new ApiError(message || (res.status===404?"This backend endpoint is not available or the connection has closed.":`Request failed (HTTP ${res.status}).`),res.status,detail?.code);
    }
    return body;
  } catch(error) {
    if(error.name==="AbortError" && !signal?.aborted)throw new Error("The backend request timed out.");
    throw error;
  } finally {clearTimeout(timer);signal?.removeEventListener("abort",abort);}
}
export const getHealth=signal=>request("/api/health",{signal});
export const getConnections=signal=>request("/api/connections",{signal});
export const getAudit=signal=>request("/api/audit?limit=50",{signal});
export const getQuarantine=signal=>request("/api/quarantine/list",{signal});
export const quarantineConnection=id=>request("/api/quarantine",{method:"POST",body:JSON.stringify({conn_id:id})});

export const getIncidents=async signal=>validateIncidentSnapshot(await request("/api/incidents",{signal}));
