import test from "node:test";
import assert from "node:assert/strict";
import {geoDistance} from "d3-geo";
import {incidentRoutes,layoutRoutes,arcSampler,visibleRoutes,severityColor} from "../src/routeGeometry.js";
import {routeColor} from "../src/data.js";
const row={id:"a",latitude_src:43,longitude_src:-89,latitude_dest:51,longitude_dest:0,severity:"low"};
test("incidents use each row's source and all four severity colors",()=>{
 const routes=incidentRoutes([row,{...row,id:"b",latitude_src:1,longitude_src:103}]);
 assert.deepEqual(routes[1].observedOrigin,{lat:1,lng:103});
 assert.equal(routes[0].lat,51);
 assert.equal(new Set(["low","medium","high","critical"].map(severityColor)).size,4);
 assert.equal(routeColor({...routes[0],severity:"critical"}),severityColor("critical"));
 assert.equal(severityColor("bad"),severityColor("unknown"));
});
test("duplicate and reversed routes get stable, bounded distinct lanes",()=>{
 const rows=[row,{...row,id:"b"},{...row,id:"c",latitude_src:51,longitude_src:0,latitude_dest:43,longitude_dest:-89}];
 const routes=layoutRoutes(incidentRoutes(rows));
 const reversed=layoutRoutes(incidentRoutes([...rows].reverse()));
 assert.deepEqual(routes.map(r=>r.lane),[-1,0,1]);
 for(const r of routes)assert.equal(r.lane,reversed.find(x=>x.id===r.id).lane);
 const middle=routes.map(r=>arcSampler(r)(.5));
 assert.equal(new Set(middle.map(p=>JSON.stringify(p.coord))).size,3);
 for(const p of middle){assert.ok(geoDistance(p.coord,middle[1].coord)<.04);assert.ok(Math.abs(p.elevation-1.22)<.019);}
 for(const r of routes){
  const sample=arcSampler(r);
  assert.deepEqual(sample(0),{coord:[r.observedOrigin.lng,r.observedOrigin.lat],elevation:1});
  assert.deepEqual(sample(1),{coord:[r.lng,r.lat],elevation:1});
 }
});
test("coincident, polar, antimeridian and antipodal endpoints produce finite arcs",()=>{
 for(const coords of [[0,0,0,0],[90,0,-90,180],[0,179,0,-179],[0,0,0,180]]){
  const [latitude_src,longitude_src,latitude_dest,longitude_dest]=coords;
  const route=layoutRoutes(incidentRoutes([{...row,latitude_src,longitude_src,latitude_dest,longitude_dest}]))[0];
  const sample=arcSampler(route);
  for(let i=0;i<=64;i++){
   const point=sample(i/64);assert.ok([...point.coord,point.elevation].every(Number.isFinite));
  }
  if(coords.every(v=>v===0))assert.ok(geoDistance(sample(0).coord,sample(.5).coord)>.01);
 }
});
test("selected route beyond render cap is included and drawn last",()=>{
 const routes=Array.from({length:200},(_,i)=>({id:String(i)}));
 const shown=visibleRoutes(routes,"195");
 assert.equal(shown.length,180);assert.equal(shown.at(-1).id,"195");
 assert.equal(routes.length,200);
});

test("antipodal and nearly antipodal routes stay continuous",()=>{
 for(const coords of [[0,0,0,180],[0,0,0,179.999999],[90,0,-90,180],[45,12,-45,-168]]){
  const [latitude_src,longitude_src,latitude_dest,longitude_dest]=coords;
  const sample=arcSampler(layoutRoutes(incidentRoutes([{...row,latitude_src,longitude_src,latitude_dest,longitude_dest}]))[0]);
  for(let i=1;i<=128;i++)assert.ok(geoDistance(sample((i-1)/128).coord,sample(i/128).coord)<.04,"Arc must not jump between samples");
 }
});
