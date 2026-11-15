import test from "node:test";
import assert from "node:assert/strict";
import {validateIncidentSnapshot,mergeIncidentSnapshot} from "../src/incidentSnapshot.js";
const row={id:"one",latitude_src:43,longitude_src:-89,latitude_dest:51,longitude_dest:0,severity:"low",ip:"203.0.113.1",description:"Example"};
const snapshot={state:"ready",fetched_at:"2026-11-15T12:00:00Z",counts:{low:1},warnings:[],incidents:[row]};
test("malformed successful responses are rejected before rendering",()=>{
 for(const value of [null,{}, {...snapshot,incidents:{}},{...snapshot,incidents:[null]},{...snapshot,warnings:{}},{...snapshot,counts:{low:"1"}},{...snapshot,fetched_at:"bad"},{...snapshot,message:{}},{...snapshot,incidents:[row,row]}]){
  assert.throws(()=>validateIncidentSnapshot(value),/invalid incident response/);
 }
 for(const values of [{description:{}},{id:null},{latitude_src:91},{longitude_dest:NaN},{severity:"constructor"},{ip:{}}]){
  assert.throws(()=>validateIncidentSnapshot({...snapshot,incidents:[{...row,...values}]}),/invalid incident response/);
 }
 assert.equal(validateIncidentSnapshot(snapshot),snapshot);
});
test("backend restart preserves the last snapshot until a new successful result arrives",()=>{
 const loading={state:"loading",fetched_at:null,incidents:[],warnings:[],counts:{}};
 assert.equal(validateIncidentSnapshot(loading),loading);
 const retained=mergeIncidentSnapshot(snapshot,loading);
 assert.equal(retained.incidents,snapshot.incidents);
 assert.equal(retained.stale,true);
 assert.equal(retained.state,"refreshing");
 const empty={...snapshot,incidents:[],counts:{}};
 assert.equal(mergeIncidentSnapshot(retained,empty),empty);
 assert.equal(mergeIncidentSnapshot(null,loading),loading);
});
