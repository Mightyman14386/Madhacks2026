
const test=require('node:test');
const assert=require('node:assert/strict');
const {boot}=require('./harness.cjs');
test('analysis explains rules without writing vault or leaking raw data in report',async()=>{
 const b=boot();await b.send({type:'PG_SET_WATCHLIST',watchlist:[],neverRedact:['alice@example.com']},true);
 const r=await b.send({type:'PG_ANALYZE',text:'Alice Smith: alice@example.com'},true);
 assert.equal(r.ok,true);assert.equal(r.sanitized,'Alex Morgan: alice@example.com');assert.equal(r.baseline,'Alex Morgan: [EMAIL_1]');
 assert.equal(r.findings.find(f=>f.type==='EMAIL').action,'keep');
 assert.equal(r.findings.find(f=>f.type==='PERSON').source,'dictionary');
 assert.equal(b.state.session.pgVaultV2,undefined);
 assert.equal(JSON.stringify(r.report).includes('Alice'),false);assert.equal(JSON.stringify(r.report).includes('example.com'),false);
 assert.equal((await b.sanitize('Bob Jones')).sanitized,'Alex Morgan');
});
test('analysis follows selected destination and global pause',async()=>{
 const b=boot();await b.send({type:'PG_SET_SITE_RULE',site:'chatgpt.com',rule:'never'},true);
 const r=await b.send({type:'PG_ANALYZE',text:'Alice Smith',site:'chatgpt.com'},true);
 assert.equal(r.sanitized,'Alice Smith');assert.match(r.siteReason,/Never redact/);
 const unknown=await b.send({type:'PG_ANALYZE',text:'Alice Smith',site:'unknown.example'},true);
 assert.equal(unknown.report.redacted,1);
 const invalid=await b.send({type:'PG_ANALYZE',text:'Alice Smith',site:'ftp://example.com'},true);
 assert.equal(invalid.ok,false);
});
test('web pages cannot call the lab or obtain original findings',async()=>{
 const b=boot();assert.equal((await b.send({type:'PG_ANALYZE',text:'Alice Smith'})).ok,false);
 assert.equal((await b.send({type:'PG_RUN_CHECKS'})).ok,false);
});
test('built-in diagnostic uses clean rules and returns explicit expectations',async()=>{
 const b=boot();await b.watchlist(['Please']);const r=await b.send({type:'PG_RUN_CHECKS'},true);
 assert.equal(r.ok,true);assert.equal(r.total,11);assert.equal(r.passed,11);assert.equal(b.state.session.pgVaultV2,undefined);
});
test('analysis rejects oversized input and preserves HTML as inert text',async()=>{
 const b=boot();assert.equal((await b.send({type:'PG_ANALYZE',text:'x'.repeat(100001)},true)).ok,false);
 const r=await b.send({type:'PG_ANALYZE',text:'<img src=x onerror=alert(1)> alice@example.com'},true);
 assert.equal(r.ok,true);assert.ok(r.sanitized.includes('<img'));
});

test('comparison preserves remaining aliases when an earlier match is excepted',async()=>{
 const b=boot();await b.send({type:'PG_SET_WATCHLIST',watchlist:[],neverRedact:['Alice Smith']},true);
 const r=await b.send({type:'PG_ANALYZE',text:'Alice Smith met Bob Jones.'},true);
 assert.equal(r.baseline,'Alex Morgan met Jamie Parker.');assert.equal(r.sanitized,'Alice Smith met Jamie Parker.');
});
