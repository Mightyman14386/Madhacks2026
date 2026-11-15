
const test=require("node:test"),assert=require("node:assert/strict"),fs=require("node:fs"),path=require("node:path"),crypto=require("node:crypto");
const {boot,plain,root}=require("./harness.cjs");const {detector}=boot();
const values=text=>plain(detector.collect(text)).map(m=>m.value);
test("bundled dataset is large, reproducible and records its sources",()=>{
 const meta=JSON.parse(fs.readFileSync(path.join(root,"vendor/names.metadata.json")));
 assert.ok(meta.uniqueNames>100000);assert.equal(meta.sources.length,3);
 assert.equal(meta.bundleSha256,crypto.createHash("sha256").update(fs.readFileSync(path.join(root,"vendor/names.js"))).digest("hex"));
 assert.ok(meta.localAdditions.some(a=>a.name==="Stavan"));
});
test("reported names redact without manual watchlist entries",()=>{
 for(const text of ["Raghav","Stavan","raghav","stavan"])assert.deepEqual(values(text),[text]);
 assert.deepEqual(values("Raghav met Stavan."),["Raghav","Stavan"]);
 assert.deepEqual(values("Raghav Patel met Stavan Shah."),["Raghav Patel","Stavan Shah"]);
});
test("broader vocabulary covers different naming traditions and diacritics",()=>{
 for(const name of ["Saoirse","Aarav","Priya","Chinedu","Fatima","Ximena","Jos\u00e9","S\u00f8ren","\u0141ukasz","Am\u00e9lie"])assert.deepEqual(values(name),[name],name);
 const text="My name is raghav";assert.deepEqual(values(text),["raghav"]);
});
test("dictionary lookup handles decomposed Unicode and preserves original offsets",()=>{
 const text="\ud83d\ude00 Am\u0065\u0301lie met Raghav.";const matches=plain(detector.collect(text));
 assert.deepEqual(matches.map(m=>m.value),["Am\u0065\u0301lie","Raghav"]);
 matches.forEach(m=>assert.equal(text.slice(m.start,m.end),m.value));
});
test("common words and headings do not become names just because they occur in the data",()=>{
 for(const text of ["May I send the report?","Will you send the meeting notes?","The Rose blooms in June.","Please summarize the meeting notes.","Report Title: Meeting Notes","QuarterlyReportForEngineeringTeam2026"])assert.deepEqual(values(text),[],text);
 assert.deepEqual(values("Name: Rose"),["Rose"]);
});
test("names do not match inside identifiers or URLs and email matches stay intact",()=>{
 assert.deepEqual(values("Raghav123 and myRaghavVariable"),[]);
 assert.deepEqual(values("https://raghav.example.com/Raghav"),[]);
 const matches=plain(detector.collect("raghav@example.com Stavan"));
 assert.deepEqual(matches.map(m=>[m.type,m.value]),[["EMAIL","raghav@example.com"],["PERSON","Stavan"]]);
});
test("exceptions apply to full parsed names and explicit classifications still win",()=>{
 assert.deepEqual(plain(detector.collect("Raghav Patel",[],["Raghav"])),[]);
 assert.equal(detector.collect("Raghav",[{text:"Raghav",type:"ORG"}])[0].type,"ORG");
});
test("possessive suffix is preserved instead of becoming part of the alias",()=>{
 const text="Raghav\u2019s email";const matches=detector.collect(text);
 assert.equal(detector.render(text,matches,["Alex Morgan"]),"Alex Morgan\u2019s email");
});
test("new names get stable session aliases and can be exempted",async()=>{
 const b=boot();
 assert.equal((await b.sanitize("Raghav met Stavan. Raghav left.")).sanitized,"Alex Morgan met Jamie Parker. Alex Morgan left.");
 await b.send({type:"PG_SET_WATCHLIST",watchlist:[],neverRedact:["Stavan"]},true);
 assert.equal((await b.sanitize("Raghav met Stavan.")).sanitized,"Alex Morgan met Stavan.");
});
