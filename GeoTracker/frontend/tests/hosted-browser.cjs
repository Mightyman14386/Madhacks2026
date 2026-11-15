const fs=require("node:fs"),path=require("node:path"),assert=require("node:assert/strict");
const bundled=path.resolve(__dirname,"../../../paste-guard/node_modules/.cache/ms-playwright");
if(!process.env.PLAYWRIGHT_BROWSERS_PATH&&fs.existsSync(bundled))process.env.PLAYWRIGHT_BROWSERS_PATH=bundled;
const {chromium}=require("playwright");
(async()=>{
 const base=process.env.HOSTED_TEST_URL||"http://127.0.0.1:8091";
 const browser=await chromium.launch({channel:"chromium",headless:true});
 try{
  const page=await browser.newPage(),errors=[],api=[];
  page.on("pageerror",e=>errors.push(e.message));
  page.on("request",r=>{if(new URL(r.url()).pathname.startsWith("/api/"))api.push(r.url());});
  await page.route(base+"/api/incidents",r=>r.fulfill({contentType:"application/json",body:JSON.stringify({state:"ready",fetched_at:new Date().toISOString(),incidents:[],counts:{},warnings:[],stale:false})}));
  await page.goto(base);
  await page.getByText("No incidents returned",{exact:true}).waitFor();
  await page.getByRole("button",{name:"Device traffic",exact:true}).click();
  await page.getByText(/You are using the hosted learning experience/).waitFor();
  assert.ok(api.length>0&&api.every(url=>new URL(url).origin===new URL(base).origin));
  assert.deepEqual(errors,[]);
  console.log("PASS: production assets, same-origin API, hosted-mode explanation, no browser errors.");
 }finally{await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
