// Extension-only, disposable analysis. No vault writes or network requests.
const PG_REASONS = {
  pattern: "Matched a structured pattern and its validation rules.",
  watchlist: "Matched an explicit always-redact phrase.",
  name: "Compromise identified a likely person name using local language rules."
};
const PG_CHALLENGES = [
  {name:"Full person name",text:"Alice Smith met Bob Jones.",expected:["PERSON","PERSON"]},
  {name:"Email inside a sentence",text:"Contact alice@example.com.",expected:["EMAIL"]},
  {name:"Valid card checksum",text:"4111 1111 1111 1111",expected:["CARD"]},
  {name:"Reject repeated-zero card",text:"0000000000000000",expected:[]},
  {name:"Ordinary long identifier",text:"QuarterlyReportForEngineeringTeam2026",expected:[]},
  {name:"IPv4 boundaries",text:"192.168.1.25",expected:["IP"]},
  {name:"Invalid IPv4 chain",text:"999.192.168.1.25",expected:[]},
  {name:"Contextual secret",text:"api_key=abcdef0123456789",expected:["KEY"]},
  {name:"Phone number",text:"+1 (608) 555-1234",expected:["PHONE"]},
  {name:"Plain prose",text:"Please summarize the meeting notes.",expected:[]}
];
function previewText(text,matches,aliases=new Map()) {
  const counters={};
  const labels=matches.map(match=>{
    const key=keyFor(match.type,match.value);
    if(!aliases.has(key)){
      let label;
      do { counters[match.type]=(counters[match.type]||0)+1; label=aliasFor(match.type,counters[match.type]); }
      while(text.toLowerCase().includes(label.toLowerCase()) || [...aliases.values()].includes(label));
      aliases.set(key,label);
    }
    return aliases.get(key);
  });
  return PasteGuard.render(text,matches,labels);
}
async function analyzePolicy(text,site) {
  if(typeof text!=="string" || text.length>100000) throw new Error("Enter up to 100,000 characters.");
  const {watchlist=[]}=await chrome.storage.local.get("watchlist");
  const {neverRedact=[]}=await chrome.storage.local.get("neverRedact");
  const baseline=PasteGuard.collect(text,watchlist,[]);
  let selected=PasteGuard.collect(text,watchlist,neverRedact);
  let siteReason="";
  const settings=await getSettings();
  // Without a destination, evaluate phrase rules even while the global switch is off.
  if(site) {
    const host=pgNormalizeSite(site);
    if(!settings.enabled) siteReason="The master protection switch is paused.";
    else if(settings.neverSites.includes(host)) siteReason="This website is on your Never redact list.";
    else if(!PG_SITES.includes(host) && !settings.sites.includes(host)) siteReason="This website is not enabled for Paste Guard.";
    else if(!PG_SITES.includes(host) && chrome.permissions && !(await chrome.permissions.contains({origins:[pgOriginFor(host)]}))) siteReason="Chrome access to this website has not been granted.";
    if(siteReason) selected=[];
  }
  const selectedKeys=new Set(selected.map(m=>m.start+":"+m.end+":"+m.type));
  const all=new Map([...baseline,...selected].map(m=>[m.start+":"+m.end+":"+m.type,m]));
  const findings=[...all.entries()].map(([key,m])=>({
    type:m.type,value:m.value,start:m.start,end:m.end,source:m.source,
    action:selectedKeys.has(key)?"redact":"keep",
    reason:selectedKeys.has(key)?PG_REASONS[m.source]:(siteReason || "A never-redact phrase overlaps this detection.")
  })).sort((a,b)=>a.start-b.start);
  const byType={};
  for(const m of selected) byType[m.type]=(byType[m.type]||0)+1;
  const report={
    schemaVersion:1,extensionVersion:chrome.runtime.getManifest?.().version || "development",
    redacted:selected.length,kept:findings.filter(f=>f.action==="keep").length,
    byType,scope:"Local preview only. Counts are not a guarantee that all sensitive data was found."
  };
  const aliases=new Map();
  return {baseline:previewText(text,baseline,aliases),sanitized:previewText(text,selected,aliases),findings,siteReason,report};
}
function runChallenges() {
  const results=PG_CHALLENGES.map(c=>{
    const actual=PasteGuard.collect(c.text,[],[]).map(m=>m.type);
    return {name:c.name,expected:c.expected,actual,passed:JSON.stringify(actual)===JSON.stringify(c.expected)};
  });
  return {results,passed:results.filter(r=>r.passed).length,total:results.length};
}
