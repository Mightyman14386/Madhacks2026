
const test=require('node:test');
const assert=require('node:assert/strict');
const {boot}=require('./harness.cjs');
test('Always On redacts with the default switch off, including after restart',async()=>{
 const b=boot();await b.send({type:'PG_SET_ENABLED',enabled:false},true);
 assert.equal((await b.sanitize('alice@example.com')).sanitized,'[EMAIL_1]');
 const restarted=boot({state:b.state});
 assert.equal((await restarted.sanitize('alice@example.com')).sanitized,'[EMAIL_1]');
});
test('Never redact beats Always On regardless of switch position',async()=>{
 for(const enabled of [true,false]){
  const b=boot({state:{session:{},sync:{},local:{enabled,sites:['chatgpt.com'],neverSites:['chatgpt.com']}}});
  assert.equal((await b.sanitize('alice@example.com')).sanitized,'alice@example.com');
 }
});
test('phrase exceptions still apply to Always On with protection off',async()=>{
 const b=boot();await b.send({type:'PG_SET_ENABLED',enabled:false},true);
 await b.send({type:'PG_SET_WATCHLIST',watchlist:[],neverRedact:['alice@example.com']},true);
 assert.equal((await b.sanitize('alice@example.com bob@example.com')).sanitized,'alice@example.com [EMAIL_1]');
});
test('preview matches Always On while protection is off',async()=>{
 const b=boot();await b.send({type:'PG_SET_ENABLED',enabled:false},true);
 const preview=await b.send({type:'PG_ANALYZE',text:'alice@example.com',site:'chatgpt.com'},true);
 assert.equal(preview.sanitized,'[EMAIL_1]');assert.equal(preview.siteReason,'');
 const unlisted=await b.send({type:'PG_ANALYZE',text:'alice@example.com',site:'unknown.example'},true);
 assert.equal(unlisted.sanitized,'alice@example.com');
});
test('unlisted sites follow the switch',()=>{
 const b=boot();const policy=b.context.pgShouldRedact;
 for(const enabled of [true,false]){
  assert.equal(policy('unknown.example',{enabled,sites:[],neverSites:[]}),enabled);
  assert.equal(policy('chatgpt.com',{enabled,sites:['chatgpt.com'],neverSites:[]}),true);
 }
 b.context.PG_SITES=['default.example'];
 assert.equal(policy('default.example',{enabled:true,sites:[],neverSites:[]}),true);
 assert.equal(policy('default.example',{enabled:false,sites:[],neverSites:[]}),false);
});

test('unlisted websites redact only while default protection is on',async()=>{
 const b=boot();
 const sender={id:'test-extension',url:'https://unlisted.example/editor'};
 assert.equal((await b.send({type:'PG_SANITIZE',text:'alice@example.com'},sender)).sanitized,'[EMAIL_1]');
 const preview=await b.send({type:'PG_ANALYZE',text:'alice@example.com',site:'unlisted.example'},true);
 assert.equal(preview.sanitized,'[EMAIL_1]');
 await b.send({type:'PG_SET_ENABLED',enabled:false},true);
 assert.equal((await b.send({type:'PG_SANITIZE',text:'alice@example.com'},sender)).sanitized,'alice@example.com');
});
test('all combinations of website overrides follow precedence',()=>{
 const b=boot();
 for(const enabled of [true,false])for(const always of [true,false])for(const never of [true,false]){
  assert.equal(b.context.pgShouldRedact('x.example',{enabled,sites:always?['x.example']:[],neverSites:never?['x.example']:[]}),!never&&(always||enabled));
 }
});

test('saving Always On does not request or depend on optional Chrome permissions',async()=>{
 const b=boot();let permissionChecks=0;
 b.context.chrome.permissions={contains:async()=>{permissionChecks++;return false;}};
 const result=await b.send({type:'PG_ADD_SITE',site:'https://Example.org/path'},true);
 assert.equal(result.ok,true);assert.ok(result.sites.includes('example.org'));assert.equal(permissionChecks,0);
});
test('Always On additions deduplicate and move out of Never redact',async()=>{
 const b=boot();
 await b.send({type:'PG_SET_SITE_RULE',site:'example.org',rule:'never'},true);
 for(const input of ['https://EXAMPLE.org/path','example.org']){
  const r=await b.send({type:'PG_SET_SITE_RULE',site:input,rule:'always'},true);assert.equal(r.ok,true);
 }
 assert.equal(b.state.local.sites.filter(s=>s==='example.org').length,1);assert.ok(!b.state.local.neverSites.includes('example.org'));
});
test('invalid website input and list limits preserve saved rules',async()=>{
 const b=boot();const initial=[...b.state.local.sites];
 assert.equal((await b.send({type:'PG_ADD_SITE',site:'ftp://bad.example'},true)).ok,false);
 assert.deepEqual(b.state.local.sites,initial);
 b.state.local.sites=Array.from({length:50},(_,i)=>'site'+i+'.example');
 const result=await b.send({type:'PG_ADD_SITE',site:'new.example'},true);
 assert.equal(result.ok,false);assert.equal(b.state.local.sites.length,50);
});
