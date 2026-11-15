importScripts("config.js", "vendor/compromise.js", "vendor/names.js", "names.js", "detector.js", "lab.js");

// One worker owns the vault. Queue initialization, allocation and persistence
// together so concurrent tabs cannot assign the same alias to different values.
let queue = Promise.resolve();
let initialized = false;
const FIRST_NAMES = ["Alex", "Jamie", "Taylor", "Morgan", "Casey", "Riley", "Avery", "Quinn"];
const LAST_NAMES = ["Morgan", "Parker", "Reed", "Bennett", "Hayes", "Brooks", "Ellis", "Lane"];
const TYPES = new Set(["PERSON", "ORG", "CONFIDENTIAL", "WATCH", "EMAIL", "PHONE", "CARD", "SSN", "IP", "KEY", "JWT"]);
const emptyVault = () => ({ version: 2, entries: {}, counters: {} });
function keyFor(type, value) {
  const folded = ["PERSON", "ORG", "WATCH", "CONFIDENTIAL"].includes(type);
  return JSON.stringify([type, folded ? value.toLowerCase() : value]);
}

async function initialize() {
  if (initialized) return;
  await chrome.storage.session.setAccessLevel({ accessLevel: "TRUSTED_CONTEXTS" });
  await chrome.storage.local.setAccessLevel({ accessLevel: "TRUSTED_CONTEXTS" });
  const local = await chrome.storage.local.get("watchlist");
  const legacy = await chrome.storage.sync.get("watchlist");
  if (local.watchlist === undefined) await chrome.storage.local.set({ watchlist: PasteGuard.normalizeWatchlist(legacy.watchlist) });
  // Do not remove the old synced copy until its local replacement is saved.
  if (legacy.watchlist !== undefined) await chrome.storage.sync.remove("watchlist");
  await chrome.storage.session.remove("pgVault"); // obsolete per-tab allocation format
  initialized = true;
}

function validateVault(vault) {
  if (!vault || vault.version !== 2 || !vault.entries || !vault.counters
      || typeof vault.entries !== "object" || Array.isArray(vault.entries)
      || typeof vault.counters !== "object" || Array.isArray(vault.counters)) throw new Error("Invalid session vault. Restart the browser before pasting.");
  const aliases = new Set();
  for (const [key, entry] of Object.entries(vault.entries)) {
    if (!entry || !TYPES.has(entry.type) || typeof entry.value !== "string"
        || typeof entry.alias !== "string" || !entry.alias || aliases.has(entry.alias.toLowerCase())
        || key !== keyFor(entry.type, entry.value)) throw new Error("Invalid session vault. Restart the browser before pasting.");
    aliases.add(entry.alias.toLowerCase());
  }
  for (const [type, count] of Object.entries(vault.counters)) {
    if (!TYPES.has(type) || !Number.isSafeInteger(count) || count < 0 || count > 1000000) throw new Error("Invalid session counter.");
  }
  return vault;
}

function aliasFor(type, number) {
  if (type === "PERSON") {
    const index = number - 1;
    const name = `${FIRST_NAMES[index % FIRST_NAMES.length]} ${LAST_NAMES[(Math.floor(index / FIRST_NAMES.length) + index) % LAST_NAMES.length]}`;
    const cycle = Math.floor(index / (FIRST_NAMES.length * LAST_NAMES.length));
    return cycle ? `${name} ${cycle + 1}` : name;
  }
  if (type === "ORG") return `Example Company ${number}`;
  return `[${type}_${number}]`;
}

async function sanitize(text) {
  const { watchlist } = await chrome.storage.local.get("watchlist");
  const { neverRedact = [] } = await chrome.storage.local.get("neverRedact");
  const matches = PasteGuard.collect(text, watchlist, neverRedact);
  if (!matches.length) return { sanitized: text, found: [] };
  const stored = await chrome.storage.session.get("pgVaultV2");
  const vault = validateVault(stored.pgVaultV2 === undefined ? emptyVault() : stored.pgVaultV2);
  const occupied = new Set(Object.values(vault.entries).map((entry) => entry.alias.toLowerCase()));
  const original = text.toLowerCase();
  const replacements = matches.map((match) => {
    const key = keyFor(match.type, match.value);
    const existing = vault.entries[key];
    if (existing) {
      if (original.includes(existing.alias.toLowerCase())) throw new Error("This paste contains an existing replacement alias. Remove that alias or paste the original text separately.");
      return existing.alias;
    }
    let alias;
    do {
      const number = (vault.counters[match.type] || 0) + 1;
      if (number > 1000000) throw new Error("Session alias limit reached. Restart the browser.");
      vault.counters[match.type] = number;
      alias = aliasFor(match.type, number);
    } while (occupied.has(alias.toLowerCase()) || original.includes(alias.toLowerCase()));
    occupied.add(alias.toLowerCase());
    vault.entries[key] = { type: match.type, value: match.value, alias };
    return alias;
  });
  // Never insert an alias unless its reverse mapping was successfully saved.
  await chrome.storage.session.set({ pgVaultV2: vault });
  return {
    sanitized: PasteGuard.render(text, matches, replacements),
    found: matches.map((match, i) => ({ type: match.type, label: replacements[i], start: match.start, end: match.end })),
  };
}

// ---------- Popup settings: master switch + sites the user added ----------
// Stored in chrome.storage.local. Only on/off and hostnames live here,
// never any pasted or real values.
const SITE_SCRIPT_ID = "pg-user-sites";
const MAX_SITES = 50;

async function getSettings() {
  const { enabled } = await chrome.storage.local.get("enabled");
  const { sites } = await chrome.storage.local.get("sites");
  return {
    enabled: enabled !== false, // on unless the user turned it off
    sites: Array.isArray(sites) ? sites.filter((s) => typeof s === "string") : [],
    neverSites: (await chrome.storage.local.get("neverSites")).neverSites || [],
  };
}

// What the popup shows. Only counts per type are sent, never real values.
async function settingsView() {
  const settings = await getSettings();
  const stored = await chrome.storage.session.get("pgVaultV2");
  const byType = {};
  for (const entry of Object.values(stored.pgVaultV2?.entries || {})) {
    if (TYPES.has(entry?.type)) byType[entry.type] = (byType[entry.type] || 0) + 1;
  }
  const protectedCount = Object.values(byType).reduce((a, b) => a + b, 0);
  return { ...settings, builtIn: PG_SITES, protectedCount, byType };
}

// Tell every open tab running Paste Guard about the new on/off state, so
// flipping the switch works instantly without reloading pages.
async function broadcastState() {
  if (chrome.runtime.sendMessage) chrome.runtime.sendMessage({type:"PG_RULES_CHANGED"}).catch(() => {});
  if (!chrome.tabs) return;
  const { enabled, sites, neverSites } = await getSettings();
  for (const tab of await chrome.tabs.query({})) {
    chrome.tabs.sendMessage(tab.id, { type: "PG_STATE", enabled, sites, neverSites }).catch(() => {});
  }
}

// Clear registrations left over from the former per-site injection model.
async function syncSiteScripts() {
  // The manifest now covers ordinary web pages. Remove legacy registrations
  // so older per-site scripts cannot cause duplicate injection.
  if (!chrome.scripting) return;
  const existing = await chrome.scripting.getRegisteredContentScripts({ ids: [SITE_SCRIPT_ID] });
  if (existing.length) await chrome.scripting.unregisterContentScripts({ ids: [SITE_SCRIPT_ID] });
}

// The manifest handles new pages. Inject into open tabs after an update.
async function injectIntoOpenTabs(hosts) {
  if (!chrome.scripting || !chrome.tabs) return;
  for (const host of hosts) {
    const tabs = await chrome.tabs.query({ url: pgOriginFor(host) }).catch(() => []);
    for (const tab of tabs) {
      chrome.scripting.executeScript({ target: { tabId: tab.id }, files: ["config.js", "content.js"] }).catch(() => {});
    }
  }
}

async function addSite(raw) {
  const host = pgNormalizeSite(raw);
  const current = await getSettings();
  if (PG_SITES.includes(host)) { await chrome.storage.local.set({ neverSites: current.neverSites.filter(s => s !== host) }); await broadcastState(); return; }
  const { sites } = await getSettings();
  if (!sites.includes(host)) {
    if (sites.length >= MAX_SITES) throw new Error(`You can add up to ${MAX_SITES} sites.`);
    await chrome.storage.local.set({ sites: [...sites, host] });
  }
  await chrome.storage.local.set({ neverSites: current.neverSites.filter(s => s !== host) });
  await syncSiteScripts();
  await injectIntoOpenTabs([host]);
  await broadcastState();
}

async function removeSite(raw, releasePermission = true) {
  const host = pgNormalizeSite(raw);
  const { sites } = await getSettings();
  await chrome.storage.local.set({ sites: sites.filter((s) => s !== host) });
  await syncSiteScripts();
  await broadcastState();
  // Keep shared web access: removing an override restores the default policy.
  // Removing an override restores the default policy; shared web access remains.
}

// ---------- Who may send which message ----------
async function setSiteRule(raw, rule) {
  const host = pgNormalizeSite(raw);
  if (!["always", "never", "default"].includes(rule)) throw new Error("Invalid website rule.");
  if (rule === "always") { await addSite(host); return settingsView(); }
  const current = await getSettings();
  const neverSites = current.neverSites.filter(s => s !== host);
  if (rule === "never") neverSites.push(host);
  if (neverSites.length > MAX_SITES) throw new Error("Use at most 50 never-redact websites.");
  await chrome.storage.local.set({ sites: current.sites.filter(s => s !== host), neverSites });
  await syncSiteScripts();
  await broadcastState();
  return settingsView();
}

const SITE_MESSAGES = new Set(["PG_SANITIZE", "PG_GET_STATE"]);
const PAGE_MESSAGES = new Set(["PG_GET_WATCHLIST", "PG_SET_WATCHLIST", "PG_GET_SETTINGS", "PG_SET_ENABLED", "PG_ADD_SITE", "PG_REMOVE_SITE", "PG_SET_SITE_RULE", "PG_ANALYZE", "PG_RUN_CHECKS"]);
const EXTENSION_PAGES = ["options.html", "popup.html", "lab.html"];

// Settings changes only from our own popup/options pages. Pastes only from
// ordinary HTTP/HTTPS pages running our content script.
async function allowedSender(sender, type) {
  if (sender.id !== chrome.runtime.id || !sender.url) return false;
  let url;
  try { url = new URL(sender.url); } catch { return false; }
  if (PAGE_MESSAGES.has(type)) return EXTENSION_PAGES.some((page) => url.href.split("#")[0] === chrome.runtime.getURL(page));
  if (!["http:", "https:"].includes(url.protocol)) return false;
  if (type === "PG_GET_STATE") return true; // harmless: tells a tab whether to stay active
  // Chrome supplies this sender for our content script. Policy is checked in handle().
  return true;
}

async function handle(message, sender) {
  switch (message.type) {
    case "PG_SANITIZE":
      // Always On sites remain protected when the default switch is off.
      if (typeof message.text !== "string") throw new Error("Invalid paste.");
      const state = await getSettings();
      if (!pgShouldRedact(new URL(sender.url).hostname, state)) return { sanitized: message.text, found: [] };
      return sanitize(message.text);
    case "PG_ANALYZE": return analyzePolicy(message.text, message.site);
    case "PG_RUN_CHECKS": return runChallenges();
    case "PG_GET_STATE": return getSettings();
    case "PG_GET_SETTINGS": return settingsView();
    case "PG_SET_ENABLED":
      if (typeof message.enabled !== "boolean") throw new Error("Invalid on/off value.");
      await chrome.storage.local.set({ enabled: message.enabled });
      await broadcastState();
      return settingsView();
    case "PG_SET_SITE_RULE": return setSiteRule(message.site, message.rule);
    case "PG_ADD_SITE": await addSite(message.site); return settingsView();
    case "PG_REMOVE_SITE": await removeSite(message.site); return settingsView();
    case "PG_SET_WATCHLIST": {
      const watchlist = PasteGuard.normalizeWatchlist(message.watchlist, true);
      const neverRedact = PasteGuard.normalizeWatchlist(message.neverRedact || [], true);
      await chrome.storage.local.set({ watchlist, neverRedact });
      if (chrome.runtime.sendMessage) chrome.runtime.sendMessage({type:"PG_RULES_CHANGED"}).catch(() => {});
      return { watchlist, neverRedact };
    }
    case "PG_GET_WATCHLIST": {
      const { watchlist } = await chrome.storage.local.get("watchlist");
      const { neverRedact = [] } = await chrome.storage.local.get("neverRedact");
      return { watchlist: PasteGuard.normalizeWatchlist(watchlist), neverRedact: PasteGuard.normalizeWatchlist(neverRedact) };
    }
  }
}

// Every request runs one at a time through the same queue.
function enqueue(work) {
  const job = queue.then(async () => { await initialize(); return work(); });
  queue = job.catch(() => {});
  return job;
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const type = message?.type;
  if (!SITE_MESSAGES.has(type) && !PAGE_MESSAGES.has(type)) return false;
  enqueue(async () => {
    if (!(await allowedSender(sender, type))) throw new Error("Paste Guard cannot handle this request from this page.");
    return handle(message, sender);
  }).then((result) => sendResponse({ ok: true, ...result }), (error) => {
    sendResponse({ ok: false, error: error instanceof Error ? error.message : "Could not safely process the paste." });
  });
  return true;
});

// Apply updates immediately to already-open ordinary web tabs. The manifest
// handles subsequent navigations. Never-redact and paused pages stand aside.
chrome.runtime.onInstalled?.addListener(() => {
  enqueue(async () => { await syncSiteScripts(); await injectIntoOpenTabs(["*"]); }).catch(() => {});
});
chrome.runtime.onStartup?.addListener(() => { enqueue(syncSiteScripts).catch(() => {}); });
