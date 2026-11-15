
const test=require('node:test');
const assert=require('node:assert/strict');
const {boot,plain}=require('./harness.cjs');
test('phrase exceptions override manual and inferred matches',()=>{
 const {detector}=boot();
 assert.deepEqual(plain(detector.collect('Alice Smith', ['Alice Smith'],['Alice Smith'])),[]);
 assert.deepEqual(plain(detector.collect('Alice Smith', [],['Alice'])),[]);
 assert.equal(detector.collect('alice@example.com bob@example.com',[],['alice@example.com']).length,1);
});
test('exception boundaries and case flags are respected',()=>{
 const {detector}=boot();
 assert.equal(detector.collect('alice@example.com',[],['ali']).length,1);
 assert.equal(detector.collect('alice@example.com',[],[{text:'ALICE@EXAMPLE.COM',type:'WATCH',caseSensitive:true}]).length,1);
});
test('phrase rules persist atomically and invalid exceptions do not overwrite',async()=>{
 const b=boot();
 assert.equal((await b.send({type:'PG_SET_WATCHLIST',watchlist:[],neverRedact:['alice@example.com']},true)).ok,true);
 assert.equal((await b.sanitize('alice@example.com')).sanitized,'alice@example.com');
 assert.equal((await b.send({type:'PG_SET_WATCHLIST',watchlist:[],neverRedact:[42]},true)).ok,false);
 assert.equal((await b.sanitize('alice@example.com')).sanitized,'alice@example.com');
});
test('never site wins and can be restored to always',async()=>{
 const b=boot();
 assert.equal((await b.send({type:'PG_SET_SITE_RULE',site:'https://chatgpt.com/path',rule:'never'},true)).ok,true);
 assert.equal((await b.sanitize('alice@example.com')).sanitized,'alice@example.com');
 assert.equal((await b.send({type:'PG_SET_SITE_RULE',site:'chatgpt.com',rule:'always'},true)).ok,true);
 assert.equal((await b.sanitize('alice@example.com')).sanitized,'[EMAIL_1]');
});
test('site rule writes from web pages are rejected',async()=>{
 const b=boot();
 assert.equal((await b.send({type:'PG_SET_SITE_RULE',site:'chatgpt.com',rule:'never'})).ok,false);
});
