(() => {
const $=id=>document.getElementById(id);
let reportData=null, revision=0;
function status(text,error=false){$("lab-status").textContent=text;$("lab-status").dataset.error=String(error);}
async function send(message){const r=await chrome.runtime.sendMessage(message);if(!r?.ok)throw Error(r?.error || "Could not complete the check.");return r;}
function invalidate(){revision++;reportData=null;$("results").hidden=true;$("baseline").textContent="";$("output").textContent="";$("findings").replaceChildren();status("Text or destination changed. Compare again to refresh the preview.");}
$("source").addEventListener("input",invalidate);$("destination").addEventListener("input",invalidate);
$("sample").addEventListener("click",()=>{$("source").value="Alice Smith met Bob Jones.\nEmail alice@example.com.\nPhone: +1 (608) 555-1234\nTest card: 4111 1111 1111 1111\nKeep this ordinary identifier: QuarterlyReportForEngineeringTeam2026";invalidate();$("source").focus();});
$("clear").addEventListener("click",()=>{$("source").value="";$("destination").value="";invalidate();status("Text and preview cleared.");});
$("analyze-form").addEventListener("submit",async e=>{
 e.preventDefault();const version=++revision;$("analyze").disabled=true;status("Checking locally...");
 try{
  const r=await send({type:"PG_ANALYZE",text:$("source").value,site:$("destination").value.trim()});
  if(version!==revision)return;
  reportData=r.report;$("baseline").textContent=r.baseline;$("output").textContent=r.sanitized;$("site-reason").textContent=r.siteReason;
  $("findings").replaceChildren();
  for(const finding of r.findings){
   const tr=document.createElement("tr");
   for(const value of [finding.value,finding.type,finding.action==="keep"?"Kept":"Redacted",finding.reason]){const td=document.createElement("td");td.textContent=value;tr.append(td);}
   tr.children[2].className="decision "+finding.action;$("findings").append(tr);
  }
  $("empty-findings").hidden=r.findings.length!==0;$("results").hidden=false;
  status(r.report.redacted+" redacted, "+r.report.kept+" kept by your rules. Preview only; no session mappings were changed.");
 }catch(error){if(version===revision){$("results").hidden=true;reportData=null;status(error.message,true);}}
 finally{$("analyze").disabled=false;}
});
$("copy").addEventListener("click",async()=>{try{await navigator.clipboard.writeText($("output").textContent);status("Preview copied. Check it before sharing.");}catch{status("Clipboard access was unavailable. Select and copy the preview manually.",true);}});
$("export").addEventListener("click",()=>{
 if(!reportData)return;const url=URL.createObjectURL(new Blob([JSON.stringify(reportData,null,2)],{type:"application/json"}));
 const a=document.createElement("a");a.href=url;a.download="paste-guard-counts.json";a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);status("Counts-only report exported.");
});
$("run-checks").addEventListener("click",async()=>{
 $("run-checks").disabled=true;$("check-summary").textContent="Running bundled examples...";
 try{const r=await send({type:"PG_RUN_CHECKS"});$("check-summary").textContent=r.passed+" / "+r.total+" synthetic checks passed. This is not an accuracy guarantee.";$("check-results").replaceChildren();
 for(const result of r.results){const card=document.createElement("div");card.className="check"+(result.passed?"":" failed");const title=document.createElement("strong");title.textContent=(result.passed?"PASS · ":"FAIL · ")+result.name;const details=document.createElement("p");details.textContent="Expected: "+(result.expected.join(", ")||"no matches")+" · Found: "+(result.actual.join(", ")||"no matches");card.append(title,details);$("check-results").append(card);}
 }catch(e){$("check-summary").textContent=e.message;}finally{$("run-checks").disabled=false;}
});
// A rule change elsewhere makes the displayed preview stale.
chrome.runtime.onMessage.addListener(m=>{if(m?.type==="PG_RULES_CHANGED" || m?.type==="PG_STATE")invalidate();});

})();
