(() => {
const $ = id => document.getElementById(id);
let settings;
let dirty = false;
function report(message, error = false) { $("status").textContent = message; $("status").dataset.error = String(error); }
function changed() { dirty = true; $("save-label").textContent = "You have unsaved phrase changes."; report("Save to apply your phrase rules."); }
async function send(message) { const r = await chrome.runtime.sendMessage(message); if (!r?.ok) throw new Error(r?.error || "Could not save settings."); return r; }
function row(entry = { text: "", type: "PERSON", caseSensitive: false }, exception = false) {
  const wrapper = document.createElement("div"); wrapper.className = "entry";
  const label = document.createElement("label"); label.className = "term"; label.textContent = "Phrase";
  const input = document.createElement("input"); input.type = "text"; input.maxLength = 200; input.required = true; input.value = entry.text; input.placeholder = exception ? "A phrase to keep" : "Alice Smith"; label.append(input);
  wrapper.append(label);
  if (!exception) {
    const category = document.createElement("label"); category.textContent = "Replace as";
    const select = document.createElement("select");
    for (const [value, title] of [["PERSON","Person"],["ORG","Organization"],["CONFIDENTIAL","Confidential phrase"],["WATCH","Generic term"]]) { const option = document.createElement("option"); option.value = value; option.textContent = title; select.append(option); }
    select.value = entry.type; category.append(select); wrapper.append(category);
  }
  const caseLabel = document.createElement("label"); caseLabel.className = "case";
  const checkbox = document.createElement("input"); checkbox.type = "checkbox"; checkbox.checked = entry.caseSensitive; caseLabel.append(checkbox, "Match case");
  const remove = document.createElement("button"); remove.type = "button"; remove.className = "remove"; remove.textContent = "Remove"; remove.setAttribute("aria-label","Remove phrase");
  remove.addEventListener("click", () => { wrapper.remove(); changed(); });
  wrapper.append(caseLabel, remove); wrapper.addEventListener("input", changed);
  $(exception ? "exceptions" : "entries").append(wrapper);
}
function siteRow(host, rule) {
  const row = document.createElement("div"); row.className = "site-row";
  const avatar = document.createElement("span"); avatar.className = "site-avatar"; avatar.textContent = host[0].toUpperCase();
  const name = document.createElement("span"); name.className = "host"; name.textContent = host;
  const button = document.createElement("button"); button.type = "button"; button.className = "remove";
  button.textContent = rule === "always" && settings.builtIn.includes(host) ? "Pause" : "Remove";
  button.setAttribute("aria-label",button.textContent + " " + host);
  button.addEventListener("click", async () => {
    button.disabled = true;
    try { renderSites(await send({type:"PG_SET_SITE_RULE", site:host, rule:rule === "always" && settings.builtIn.includes(host) ? "never" : "default"})); report("Website rule saved." + (dirty ? " Phrase changes are still unsaved." : "")); }
    catch(e) { report(e.message,true); button.disabled=false; }
  });
  row.append(avatar,name,button); return row;
}
function renderSites(next) {
  settings = next;
  const never = next.neverSites || [];
  const always = [...new Set([...next.builtIn,...next.sites])].filter(host => !never.includes(host));
  for (const [rule, hosts] of [["always",always],["never",never]]) {
    const container = $(rule+"-sites"); container.replaceChildren(...hosts.map(host=>siteRow(host,rule)));
    if (!hosts.length) { const empty = document.createElement("div"); empty.className="empty"; empty.textContent="No websites in this list."; container.append(empty); }
  }
}
async function addSite(rule) {
  let host;
  try { host = pgNormalizeSite($(rule+"-input").value); } catch(e) { report(e.message,true); return; }
  const button=$(rule+"-add");
  if (button.disabled) return;
  button.disabled=true;
  try {
    renderSites(await send({type:"PG_SET_SITE_RULE",site:host,rule}));
    $(rule+"-input").value="";
    report("Website rule saved." + (dirty ? " Phrase changes are still unsaved." : ""));
  } catch(e) { report(e.message,true); }
  finally { button.disabled=false; }
}
for(const rule of ["always","never"]) {
  $(rule+"-add").addEventListener("click",()=>addSite(rule));
  $(rule+"-input").addEventListener("keydown",e=>{if(e.key==="Enter"){e.preventDefault();addSite(rule);}});
}
$("add").addEventListener("click",()=>{row();changed();});
$("add-never").addEventListener("click",()=>{row({text:"",type:"WATCH",caseSensitive:false},true);changed();});
function readRows(id) { return [...$(id).children].map(entry=>({text:entry.querySelector("input[type=text]").value.trim(),type:entry.querySelector("select")?.value || "WATCH",caseSensitive:entry.querySelector("input[type=checkbox]").checked})); }
$("settings").addEventListener("submit",async event=>{
  event.preventDefault(); $("fields").disabled=true;
  try { await send({type:"PG_SET_WATCHLIST",watchlist:readRows("entries"),neverRedact:readRows("exceptions")}); dirty=false; $("save-label").textContent="All phrase rules saved."; report("Saved on this device. New pastes use these rules."); }
  catch(e){report(e.message,true);} finally{$("fields").disabled=false;}
});
window.addEventListener("beforeunload",e=>{if(dirty){e.preventDefault();e.returnValue="";}});
void(async()=>{
  try { const [sites,phrases]=await Promise.all([send({type:"PG_GET_SETTINGS"}),send({type:"PG_GET_WATCHLIST"})]); renderSites(sites); phrases.watchlist.forEach(e=>row(e)); (phrases.neverRedact || []).forEach(e=>row(e,true)); $("fields").disabled=false; report("Ready. Your saved rules are up to date."); }
  catch(e){report(e.message+" Reload this page to retry.",true);}
})();

})();
