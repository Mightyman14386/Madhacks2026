export const SEVERITY_COLORS={low:"#91cbc0",medium:"#e2c28b",high:"#eda58b",critical:"#d69cdb",unknown:"#93a3b3"};
export const severityColor=value=>SEVERITY_COLORS[value]||SEVERITY_COLORS.unknown;
export const incidentRoutes=rows=>rows.map(row=>({...row,kind:"incident",observedOrigin:{lat:row.latitude_src,lng:row.longitude_src},lat:row.latitude_dest,lng:row.longitude_dest}));
const endpoint=p=>[p.lat,p.lng].map(n=>n.toFixed(6)).join(",");
const radians=Math.PI/180;
const vector=([lng,lat])=>[Math.cos(lat*radians)*Math.cos(lng*radians),Math.cos(lat*radians)*Math.sin(lng*radians),Math.sin(lat*radians)];
const cross=(a,b)=>[a[1]*b[2]-a[2]*b[1],a[2]*b[0]-a[0]*b[2],a[0]*b[1]-a[1]*b[0]];
const norm=a=>{const length=Math.hypot(...a);return a.map(v=>v/length);};
// Assign stable lanes to the full route set before filtering or applying the render cap.
export function layoutRoutes(routes,origin) {
 const groups=new Map();
 const result=routes.map(route=>{
  const home=route.observedOrigin||origin;
  if(!home)return {...route,lane:0};
  const a=endpoint(home),b=endpoint(route),key=[a,b].sort().join("|");
  const item={...route,observedOrigin:home,lane:0,canonicalForward:a<=b};
  if(!groups.has(key))groups.set(key,[]);
  groups.get(key).push(item);return item;
 });
 for(const group of groups.values()){
  group.sort((a,b)=>a.id.localeCompare(b.id));
  group.forEach((route,i)=>{route.lane=group.length===1?0:(2*i/(group.length-1)-1);});
 }
 return result;
}
export function visibleRoutes(routes,selected,limit=180) {
 const subset=routes.slice(0,limit),chosen=routes.find(r=>r.id===selected);
 if(chosen&&!subset.includes(chosen)){if(subset.length===limit)subset.pop();subset.push(chosen);}
 return subset.sort((a,b)=>Number(a.id===selected)-Number(b.id===selected));
}
export function arcSampler(route) {
 const home=route.observedOrigin,src=[home.lng,home.lat],dest=[route.lng,route.lat];
 const a=vector(src),b=vector(dest),product=a.reduce((sum,n,i)=>sum+n*b[i],0);
 let normal=cross(a,b);
 const crossLength=Math.hypot(...normal),angle=Math.atan2(crossLength,product),direction=route.canonicalForward===false?-1:1;
 // atan2 and a tangent basis stay stable near antipodes; dividing by sin(pi) does not.
 if(crossLength<1e-12){
  const anchor=direction===1?a:b;
  normal=cross(anchor,Math.abs(anchor[2])<.9?[0,0,1]:[0,1,0]).map(n=>n*direction);
 }
 normal=norm(normal);
 const pathTangent=norm(cross(normal,a));
 normal=normal.map(n=>n*direction);
 const tangent=norm(cross(a,normal)),same=angle<1e-8,lane=route.lane||0;
 return t=>{
  if(t===0||t===1)return {coord:t===0?src:dest,elevation:1};
  const wave=Math.sin(Math.PI*t),v=a.map((n,i)=>n*Math.cos(angle*t)+pathTangent[i]*Math.sin(angle*t));
  const sideways=wave*lane*.035+(same?.035*Math.sin(2*Math.PI*t):0);
  const loop=same?.035*(1-Math.cos(2*Math.PI*t)):0;
  const adjusted=norm(v.map((n,i)=>n+normal[i]*sideways+tangent[i]*loop));
  return {coord:[Math.atan2(adjusted[1],adjusted[0])/radians,Math.asin(Math.max(-1,Math.min(1,adjusted[2])))/radians],elevation:1+wave*((same?.07:.22)+lane*.018)};
 };
}
