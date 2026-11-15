importScripts("config.js", "vendor/compromise.js", "detector.js");

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
  const matches = PasteGuard.collect(text, watchlist);
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
  if (!chrome.tabs) return;
  const { enabled, sites } = await getSettings();
  for (const tab of await chrome.tabs.query({})) {
    chrome.tabs.sendMessage(tab.id, { type: "PG_STATE", enabled, sites }).catch(() => {});
  }
}

// Ask Chrome to auto-inject our content script on every user-added site we
// still have permission for. Chrome remembers this across restarts.
async function syncSiteScripts() {
  if (!chrome.scripting || !chrome.permissions) return;
  const { sites } = await getSettings();
  const granted = [];
  for (const host of sites) {
    if (await chrome.permissions.contains({ origins: [pgOriginFor(host)] })) granted.push(host);
  }
  const existing = await chrome.scripting.getRegisteredContentScripts({ ids: [SITE_SCRIPT_ID] });
  if (existing.length) await chrome.scripting.unregisterContentScripts({ ids: [SITE_SCRIPT_ID] });
  if (!granted.length) return;
  await chrome.scripting.registerContentScripts([{
    id: SITE_SCRIPT_ID,
    matches: granted.map(pgOriginFor),
    js: ["config.js", "content.js"],
    runAt: "document_start",
  }]);
}

// Chrome only auto-injects into pages loaded AFTER registration. Inject into
// tabs that are already open on these sites so protection starts right away.
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
  if (PG_SITES.includes(host)) throw new Error(`${host} is already built in.`);
  const { sites } = await getSettings();
  if (!sites.includes(host)) {
    if (sites.length >= MAX_SITES) throw new Error(`You can add up to ${MAX_SITES} sites.`);
    if (chrome.permissions && !(await chrome.permissions.contains({ origins: [pgOriginFor(host)] }))) {
      throw new Error(`Chrome permission for ${host} was not granted.`);
    }
    await chrome.storage.local.set({ sites: [...sites, host] });
  }
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
  // Give back the site permission we asked for when it was added.
  if (releasePermission && chrome.permissions) await chrome.permissions.remove({ origins: [pgOriginFor(host)] }).catch(() => {});
}

// ---------- Who may send which message ----------
const SITE_MESSAGES = new Set(["PG_SANITIZE", "PG_GET_STATE"]);
const PAGE_MESSAGES = new Set(["PG_GET_WATCHLIST", "PG_SET_WATCHLIST", "PG_GET_SETTINGS", "PG_SET_ENABLED", "PG_ADD_SITE", "PG_REMOVE_SITE"]);
const EXTENSION_PAGES = ["options.html", "popup.html"];

// Settings changes only from our own popup/options pages. Pastes only from
// supported sites (built-in or added by the user).
async function allowedSender(sender, type) {
  if (sender.id !== chrome.runtime.id || !sender.url) return false;
  let url;
  try { url = new URL(sender.url); } catch { return false; }
  if (PAGE_MESSAGES.has(type)) return EXTENSION_PAGES.some((page) => url.href === chrome.runtime.getURL(page));
  if (url.protocol !== "https:") return false;
  if (type === "PG_GET_STATE") return true; // harmless: tells a tab whether to stay active
  return PG_SITES.includes(url.hostname) || (await getSettings()).sites.includes(url.hostname);
}

async function handle(message) {
  switch (message.type) {
    case "PG_SANITIZE":
      // Switched off: hand the text back untouched.
      if (!(await getSettings()).enabled && typeof message.text === "string") return { sanitized: message.text, found: [] };
      return sanitize(message.text);
    case "PG_GET_STATE": return getSettings();
    case "PG_GET_SETTINGS": return settingsView();
    case "PG_SET_ENABLED":
      if (typeof message.enabled !== "boolean") throw new Error("Invalid on/off value.");
      await chrome.storage.local.set({ enabled: message.enabled });
      await broadcastState();
      return settingsView();
    case "PG_ADD_SITE": await addSite(message.site); return settingsView();
    case "PG_REMOVE_SITE": await removeSite(message.site); return settingsView();
    case "PG_SET_WATCHLIST": {
      const watchlist = PasteGuard.normalizeWatchlist(message.watchlist, true);
      await chrome.storage.local.set({ watchlist });
      return { watchlist };
    }
    case "PG_GET_WATCHLIST": {
      const { watchlist } = await chrome.storage.local.get("watchlist");
      return { watchlist: PasteGuard.normalizeWatchlist(watchlist) };
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
    return handle(message);
  }).then((result) => sendResponse({ ok: true, ...result }), (error) => {
    sendResponse({ ok: false, error: error instanceof Error ? error.message : "Could not safely process the paste." });
  });
  return true;
});

// Re-register user sites whenever the extension starts or is reloaded. After a
// reload, also re-inject into open tabs (built-in and added sites) so they
// keep working without a manual refresh.
chrome.runtime.onInstalled?.addListener(() => {
  enqueue(async () => {
    await syncSiteScripts();
    await injectIntoOpenTabs([...PG_SITES, ...(await getSettings()).sites]);
  }).catch(() => {});
});
chrome.runtime.onStartup?.addListener(() => { enqueue(syncSiteScripts).catch(() => {}); });

// Chrome may close the popup while its permission prompt is open, so the
// worker also adds the site itself once permission is granted. If the user
// revokes a site in Chrome's settings, drop it from the list too.
const hostsFrom = (origins = []) => origins.map((o) => /^https:\/\/([^/*]+)\/\*$/.exec(o)?.[1]).filter(Boolean);
chrome.permissions?.onAdded?.addListener(({ origins }) => {
  for (const host of hostsFrom(origins)) enqueue(() => addSite(host)).catch(() => {});
});
chrome.permissions?.onRemoved?.addListener(({ origins }) => {
  for (const host of hostsFrom(origins)) enqueue(() => removeSite(host, false)).catch(() => {});
});
