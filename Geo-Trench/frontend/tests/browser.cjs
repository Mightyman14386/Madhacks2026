const fs=require("node:fs"),path=require("node:path"),assert=require("node:assert/strict");
const bundled=path.resolve(__dirname,"../../../paste-guard/node_modules/.cache/ms-playwright");
if(!process.env.PLAYWRIGHT_BROWSERS_PATH && fs.existsSync(bundled))process.env.PLAYWRIGHT_BROWSERS_PATH=bundled;
const {chromium}=require("playwright");
(async()=>{
 const {makeDemo}=await import("../src/data.js");
 const browser=await chromium.launch({channel:"chromium",headless:true});
 const context=await browser.newContext({viewport:{width:1440,height:1100},reducedMotion:"reduce"});
 const page=await context.newPage(),errors=[],requests=[],posts=[];
 page.on("pageerror",e=>errors.push(e.message));page.on("request",r=>requests.push(r.url()));
 let scenario="normal",inflight=0,maxInflight=0,postStatus=403;
 const snapshot=makeDemo();snapshot.connections[0].is_simulated=false;snapshot.connections[0].is_protected=true;
 snapshot.connections.push({id:"missing",process_name:"unknown.exe",remote_ip:"198.51.100.2",country_code:null,lat:null,lng:null,status:"safe",reasons:[],ancestry:[]});
 snapshot.warnings=["Test warning: visibility may be incomplete."];snapshot.truncated=true;
 snapshot.stats.total=10;
 await page.route("http://127.0.0.1:8000/**",async route=>{
  const url=new URL(route.request().url()),pathname=url.pathname;
  const reply=(body,status=200)=>route.fulfill({status,contentType:"application/json",headers:{"Access-Control-Allow-Origin":"http://localhost:5173"},body:JSON.stringify(body)});
  if(scenario==="offline")return route.abort("connectionrefused");
  if(pathname==="/api/health")return reply({status:"ok",is_admin:false,enforcement_enabled:false,geoip_fallback:true});
  if(pathname==="/api/connections"){inflight++;maxInflight=Math.max(maxInflight,inflight);await new Promise(r=>setTimeout(r,100));inflight--;return reply(snapshot);}
  if(pathname==="/api/audit")return reply([{ts:new Date().toISOString(),type:"threat_detected",severity:"high",message:"Synthetic test event",ref_id:"demo-sg"}]);
  if(pathname==="/api/quarantine/list")return reply({detail:"Not Found"},404);
  if(pathname==="/api/quarantine" && route.request().method()==="POST"){posts.push(route.request().postDataJSON());return reply(postStatus===403?{detail:{code:"PROTECTED",message:"Protected"}}:postStatus===409?{message:"Conflict"}:postStatus===404?{detail:"Not Found"}:postStatus===422?{detail:"Invalid body"}:postStatus===500?{ok:false,message:"Backend rejected the action"}:{ok:true,simulated:true},postStatus);}
  return reply({detail:"Not Found"},404);
 });
 try{
  await page.goto("http://localhost:5173");await page.getByRole("button",{name:/browser.exe United States/}).waitFor();
  assert.ok((await page.locator("body").innerText()).includes("visibility may be incomplete"));
  assert.ok((await page.locator("body").innerText()).includes("truncated"));
  assert.equal(await page.locator("canvas").count(),1);
  const box=await page.locator("canvas").boundingBox();assert.ok(box.width>500&&box.height>400);
  await page.screenshot({path:"test-results/desktop.png",fullPage:true});
  await page.locator("canvas").focus();await page.keyboard.press("ArrowRight");await page.getByRole("button",{name:"Zoom in"}).click();
  await page.mouse.move(box.x+box.width/2,box.y+box.height/2);await page.mouse.down();await page.mouse.move(box.x+box.width/2+100,box.y+box.height/2+20,{steps:8});await page.mouse.up();
  await page.locator('input[aria-label="Search connections"]').fill("Singapore");assert.equal(await page.locator(".connection-row").count(),1);
  await page.locator(".connection-row").click();await page.getByRole("heading",{name:"Connection details"}).waitFor();
  assert.ok((await page.locator(".connection-detail").innerText()).includes("DEMO_RULE"));
  await page.getByRole("button",{name:"Close connection details"}).click();await page.getByRole("textbox",{name:"Search connections"}).fill("");
  await page.getByRole("button",{name:/browser.exe United States/}).click();
  await page.getByRole("button",{name:"Request quarantine"}).click();await page.getByRole("button",{name:"Confirm request"}).click();
  await page.waitForFunction(()=>document.querySelector(".action-result")?.textContent.includes("Safety Override"));
  assert.deepEqual(Object.keys(posts[0]),["conn_id"]);assert.equal(posts[0].conn_id,"demo-us");
  for(const status of [409,404,422,500,200]){postStatus=status;await page.getByRole("button",{name:"Request quarantine"}).click();await page.getByRole("button",{name:"Confirm request"}).click();await page.waitForFunction(()=>!document.querySelector("dialog").open);assert.ok(await page.locator(".action-result").innerText());}
  await page.getByRole("button",{name:"Close connection details"}).click();
  await page.getByRole("button",{name:"Session · 15m"}).click();assert.ok((await page.locator(".list-footer").innerText()).includes("Observed this session"));
  await page.getByRole("button",{name:"Latest check"}).click();
  await page.locator(".topbar").getByRole("button",{name:"Quarantine",exact:true}).click();
  await page.getByText(/Quarantine history unavailable/).waitFor();
  await page.locator(".topbar").getByRole("button",{name:"Overview",exact:true}).click();
  const downloadPromise=page.waitForEvent("download");await page.getByRole("button",{name:"Export view"}).click();const download=await downloadPromise;
  const exported=JSON.parse(fs.readFileSync(await download.path(),"utf8"));assert.ok(exported.connections.length);assert.ok(!exported.connections.some(c=>"exe" in c));
  await page.getByRole("button",{name:"Explore demo"}).click();await page.getByText("SYNTHETIC PREVIEW",{exact:true}).waitFor();
  await page.getByRole("button",{name:/browser.exe United States/}).click();assert.ok(await page.getByRole("button",{name:/actions disabled/}).isDisabled());
  await page.getByRole("button",{name:"Close connection details"}).click();
  await page.setViewportSize({width:390,height:844});await page.screenshot({path:"test-results/mobile.png",fullPage:true});
  assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
  scenario="offline";await page.getByRole("button",{name:"Return to live"}).click();await page.getByText(/Backend unavailable at/).waitFor();
  await page.screenshot({path:"test-results/offline.png",fullPage:true});
  assert.equal(maxInflight,1);
  assert.ok(!requests.some(url=>url.includes("/api/")&& /geo\/test|process\/test|scenarios\/test|geofence|agent/.test(url)));
  assert.deepEqual(errors,[]);
  console.log("PASS: globe controls, search, details, warnings, history, ID-only quarantine, 403/404/409/422/500 responses, simulated result, unavailable records, export, demo gating, mobile layout, offline state, non-overlapping polls.");
 }finally{await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
