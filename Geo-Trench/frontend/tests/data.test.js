import test from "node:test";
import assert from "node:assert/strict";
import {hasCoordinates,mergeHistory,makeDemo} from "../src/data.js";
test("coordinates reject missing, strings, nonfinite and out-of-range locations",()=>{
 for(const point of [null,{}, {lat:null,lng:0},{lat:"43",lng:12},{lat:91,lng:0},{lat:0,lng:181},{lat:NaN,lng:0}]) assert.ok(!hasCoordinates(point));
 assert.ok(hasCoordinates({lat:0,lng:0}));
});
test("history retains stable IDs, expires old checks and preserves per-check origin",()=>{
 const now=Date.now(),origin={lat:43,lng:-89},other={lat:50,lng:0};
 let history=mergeHistory([],{origin,connections:[{id:"a",lat:3,lng:4}]},now);
 history=mergeHistory(history,{origin:other,connections:[{id:"b",lat:5,lng:6}]},now+1000);
 assert.equal(history.length,2);assert.deepEqual(history.find(c=>c.id==="a").observedOrigin,origin);
 history=mergeHistory(history,{origin:other,connections:[{id:"a",lat:7,lng:8}]},now+2000);
 assert.equal(history.length,2);assert.equal(history.find(c=>c.id==="a").lat,7);
 assert.equal(mergeHistory(history,{origin,connections:[]},now+16*60000).length,0);
});
test("history is bounded and demo is explicitly simulated",()=>{
 const connections=Array.from({length:2100},(_,i)=>({id:String(i)}));
 assert.equal(mergeHistory([],{connections}).length,2000);
 const demo=makeDemo();assert.ok(demo.connections.every(c=>c.is_simulated&&c.pid<0));assert.equal(demo.connections.length,8);
});
