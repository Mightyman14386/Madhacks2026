export function hasCoordinates(point) {
 return point && typeof point.lat==="number" && typeof point.lng==="number" && Number.isFinite(point.lat) && Number.isFinite(point.lng) && Math.abs(point.lat)<=90 && Math.abs(point.lng)<=180;
}
export function mergeHistory(previous,snapshot,now=Date.now()) {
 const next=new Map(previous.filter(item=>now-item.observedAt<15*60*1000).map(item=>[item.id,item]));
 for(const c of snapshot.connections || []) next.set(c.id,{...c,observedAt:now,observedOrigin:snapshot.origin});
 return [...next.values()].sort((a,b)=>b.observedAt-a.observedAt).slice(0,2000);
}
export const routeColor=c=>c.status==="unsafe"?(["critical","high"].includes(c.severity)?"#e7a1ad":"#e2c28b"):"#91cbc0";
export function makeDemo() {
 const origin={lat:43.0731,lng:-89.4012,name:"Madison, WI"};
 const places=[
 ["us","browser.exe","United States","US",37.75,-97.82,"Example cloud","safe","low"],
 ["de","sync.exe","Germany","DE",51.16,10.45,"Example infrastructure","safe","low"],
 ["jp","updater.exe","Japan","JP",36.20,138.25,"Example network","safe","low"],
 ["br","worker.exe","Brazil","BR",-14.23,-51.92,"Unverified network","unsafe","medium"],
 ["gb","browser.exe","United Kingdom","GB",55.37,-3.44,"Example CDN","safe","low"],
 ["sg","helper.exe","Singapore","SG",1.35,103.82,"Unverified network","unsafe","high"],
 ["au","editor.exe","Australia","AU",-25.27,133.77,"Example platform","safe","low"],
 ["za","service.exe","South Africa","ZA",-30.55,22.94,"Example network","safe","low"]
 ];
 const connections=places.map(([id,process_name,country_name,country_code,lat,lng,asn_org,status,severity],i)=>({
 id:"demo-"+id,pid:-i-1,process_name,country_name,country_code,lat,lng,asn_org,status,severity,
 remote_ip:"203.0.113."+(i+1),remote_port:443,local_ip:"192.0.2.1",local_port:49000+i,
 ancestry:["explorer.exe",process_name],is_simulated:true,is_protected:i===0,
 reasons:status==="unsafe"?["Synthetic example of a backend-reported finding."]:[],rules_fired:status==="unsafe"?["DEMO_RULE"]:[],
 first_seen:new Date(Date.now()-i*60000).toISOString()
 }));
 return {origin,connections,anycast:[{id:"demo-anycast",process_name:"dns.exe",remote_ip:"192.0.2.53",provider:"Example distributed DNS",status:"safe",is_simulated:true}],
 stats:{total:9,safe:7,unsafe:2,anycast:1,hidden_by_geofence:0,blocked_regions:[]},
 warnings:[],geoip_fallback:true,truncated:false,generated_ms:24};
}
