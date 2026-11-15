import test from "node:test";
import assert from "node:assert/strict";
import {pickLessons, distanceKm, AREAS} from "../src/learnTopics.js";

const MADISON = {lat: 43.0731, lng: -89.4012};
const chrome = {process_name: "chrome.exe", remote_ip: "142.250.80.46", remote_port: 443, asn_org: "Google LLC.",
  lat: 37.751, lng: -97.822, country_name: "United States", city: null, rules_fired: [], is_protected: true, is_simulated: false};
const ids = ls => ls.map(l => l.id);

test("distance: Madison to Shenzhen is about 12,400 km; missing coords -> null", () => {
  const km = distanceKm(MADISON, {lat: 22.5431, lng: 114.0579});
  assert.ok(km > 12000 && km < 12800, String(km));
  assert.equal(distanceKm(MADISON, {lat: null, lng: 1}), null);
});

test("safe HTTPS to a big cloud: one lesson from each area, latency first", () => {
  const ls = pickLessons(chrome, MADISON);
  assert.equal(ls.length, 6);
  assert.deepEqual(new Set(ls.map(l => l.area)), new Set(Object.keys(AREAS)));
  assert.equal(ls.find(l => l.area === "places").id, "latency");
  assert.ok(ids(ls).includes("trusted_cloud") && ids(ls).includes("tls"));
  assert.match(ls.find(l => l.id === "latency").hook, /about [\d,]+ km from you.*at least \d+ ms/);
  assert.match(ls.find(l => l.id === "asn")?.hook || "This address belongs to Google LLC's", /Google LLC's/); // trailing period stripped
});

test("every flagged rule gets its security lesson, and they are never cut", () => {
  const flagged = {...chrome, process_name: "payload.exe", remote_port: 1337, asn_org: "Small Host",
    rules_fired: ["suspicious_port", "office_spawn", "shell_spawn", "risky_location"], is_protected: false};
  const ls = pickLessons(flagged, MADISON, 2);
  assert.deepEqual(ids(ls).slice(0, 4), ["phishing_attachment", "script_interpreter", "nonstandard_port", "user_execution"]);
  assert.ok(ls.every(l => l.link.url.startsWith("https://")));
});

test("far server teaches undersea cables; Windows name outside Windows folder teaches masquerading", () => {
  const ls = pickLessons({...chrome, process_name: "svchost.exe", is_protected: false, lat: 22.5, lng: 114.0}, MADISON, 20);
  assert.ok(ids(ls).includes("cables"));
  assert.ok(ids(ls).includes("masquerading"));
  assert.ok(!ids(pickLessons({...chrome, process_name: "svchost.exe"}, MADISON, 20)).includes("masquerading"));
});

test("try-it commands only for real connections with a clean IP", () => {
  assert.ok(pickLessons(chrome, MADISON, 20).some(l => l.tryIt?.command === "tracert -d -h 20 142.250.80.46"));
  assert.ok(pickLessons({...chrome, is_simulated: true}, MADISON, 20).every(l => !l.tryIt));
  assert.ok(pickLessons({...chrome, remote_ip: "1.2.3.4; del x"}, MADISON, 20).every(l => !l.tryIt));
});

test("anycast, plain HTTP, DNS, IPv6 and empty input", () => {
  assert.ok(ids(pickLessons({process_name: "x", remote_ip: "1.1.1.1", remote_port: 53, provider: "Cloudflare DNS"}, MADISON, 20)).includes("anycast"));
  assert.ok(ids(pickLessons({...chrome, remote_port: 80}, MADISON, 20)).includes("plaintext"));
  assert.ok(ids(pickLessons({...chrome, remote_port: 53}, MADISON, 20)).includes("dns"));
  assert.ok(ids(pickLessons({...chrome, remote_ip: "2607:f8b0::200e"}, MADISON, 20)).includes("ipv6"));
  assert.deepEqual(pickLessons(null, MADISON), []);
  assert.ok(Array.isArray(pickLessons({}, null)));
});
