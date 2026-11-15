const STATES=new Set(["loading","refreshing","ready","error"]);
const SEVERITIES=new Set(["low","medium","high","critical","unknown"]);
const object=value=>value!==null&&typeof value==="object"&&!Array.isArray(value);
const coordinate=(value,maximum)=>typeof value==="number"&&Number.isFinite(value)&&Math.abs(value)<=maximum;
export function validateIncidentSnapshot(value){
 const invalid=()=>{throw new Error("The backend returned an invalid incident response.");};
 if(!object(value)||!STATES.has(value.state)||!Array.isArray(value.incidents)||!object(value.counts)||!Array.isArray(value.warnings))invalid();
 if(!value.warnings.every(w=>typeof w==="string")||!Object.values(value.counts).every(n=>Number.isInteger(n)&&n>=0))invalid();
 if(value.message!=null&&typeof value.message!=="string")invalid();
 if(value.fetched_at!=null&&(typeof value.fetched_at!=="string"||!Number.isFinite(Date.parse(value.fetched_at))))invalid();
 if(["ready","refreshing"].includes(value.state)&&!value.fetched_at)invalid();
 const ids=new Set();
 for(const row of value.incidents){
  if(!object(row)||typeof row.id!=="string"||!row.id||ids.has(row.id))invalid();
  ids.add(row.id);
  if(!coordinate(row.latitude_src,90)||!coordinate(row.latitude_dest,90)||!coordinate(row.longitude_src,180)||!coordinate(row.longitude_dest,180))invalid();
  if(!SEVERITIES.has(row.severity)||typeof row.description!=="string"||typeof row.ip!=="string")invalid();
 }
 return value;
}
export function mergeIncidentSnapshot(previous,incoming){
 if(previous?.fetched_at&&!incoming.fetched_at){
  return {...previous,state:"refreshing",stale:true,message:"Backend is reconnecting. Showing the last successful snapshot."};
 }
 return incoming;
}
