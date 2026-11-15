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

function allowedSender(sender, optionsOnly) {
  if (sender.id !== chrome.runtime.id || !sender.url) return false;
  try {
    const url = new URL(sender.url);
    if (optionsOnly) return url.href === chrome.runtime.getURL("options.html");
    return url.protocol === "https:" && PG_SITES.includes(url.hostname);
  } catch { return false; }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!["PG_SANITIZE", "PG_GET_WATCHLIST", "PG_SET_WATCHLIST"].includes(message?.type)) return false;
  if (!allowedSender(sender, message.type !== "PG_SANITIZE")) {
    sendResponse({ ok: false, error: "Paste Guard cannot handle this request from this page." });
    return false;
  }
  const job = queue.then(async () => {
    await initialize();
    if (message.type === "PG_SANITIZE") return sanitize(message.text);
    if (message.type === "PG_SET_WATCHLIST") {
      const watchlist = PasteGuard.normalizeWatchlist(message.watchlist, true);
      await chrome.storage.local.set({ watchlist });
      return { watchlist };
    }
    const { watchlist } = await chrome.storage.local.get("watchlist");
    return { watchlist: PasteGuard.normalizeWatchlist(watchlist) };
  });
  queue = job.catch(() => {});
  job.then((result) => sendResponse({ ok: true, ...result }), (error) => {
    sendResponse({ ok: false, error: error instanceof Error ? error.message : "Could not safely process the paste." });
  });
  return true;
});
