// detector.js
// Finds sensitive items in text and swaps them for labels like [EMAIL_1].
// Content scripts can't use import/export, so everything is shared
// through one global object called PasteGuard.

const PasteGuard = (() => {
  // ---------- 1. The vault: label <-> real value ----------
  // Kept in memory and mirrored to chrome.storage.session, which is wiped
  // when the browser closes. Real values NEVER go to sync or local storage.
  let vault = { labelToValue: {}, valueToLabel: {}, counters: {} };
  let watchlist = []; // user's custom words (from chrome.storage.sync)

  // Load saved vault + watchlist when the page opens.
  const ready = Promise.all([
    chrome.storage.session.get("pgVault").then((r) => { if (r.pgVault) vault = r.pgVault; }),
    chrome.storage.sync.get({ watchlist: [] }).then((r) => { watchlist = r.watchlist; }),
  ]).catch((err) => console.warn("[Paste Guard] Could not load storage:", err));

  // Stay in sync if another tab or the popup changes things.
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === "session" && changes.pgVault && changes.pgVault.newValue) vault = changes.pgVault.newValue;
    if (area === "sync" && changes.watchlist) watchlist = changes.watchlist.newValue || [];
  });

  // Return the label for a value, creating one the first time we see it.
  // This is what makes the same value always get the same label.
  function labelFor(type, value) {
    const key = type + ":" + (type === "WATCH" ? value.toLowerCase() : value);
    if (vault.valueToLabel[key]) return vault.valueToLabel[key];

    vault.counters[type] = (vault.counters[type] || 0) + 1;
    const label = `[${type}_${vault.counters[type]}]`;
    vault.valueToLabel[key] = label;
    vault.labelToValue[label] = value;
    return label;
  }

  // ---------- 2. Extra checks to avoid false alarms ----------
  // Luhn check: the checksum every real credit card number passes.
  function passesLuhn(match) {
    const digits = match.replace(/\D/g, "");
    if (digits.length < 13 || digits.length > 19) return false;
    let sum = 0;
    for (let i = 0; i < digits.length; i++) {
      let d = Number(digits[digits.length - 1 - i]);
      if (i % 2 === 1) { d *= 2; if (d > 9) d -= 9; }
      sum += d;
    }
    return sum % 10 === 0;
  }

  // A long token "looks random" if it mixes lowercase, uppercase and digits.
  function looksRandom(match) {
    return /[a-z]/.test(match) && /[A-Z]/.test(match) && /\d/.test(match);
  }

  // ---------- 3. The patterns ----------
  // Order matters: specific patterns run first so a JWT isn't
  // half-eaten by the IP or phone pattern, and so on.
  const RULES = [
    { type: "JWT",   re: /\beyJ[\w-]+\.eyJ[\w-]+\.[\w-]+/g },
    { type: "KEY",   re: /\b(?:sk-[\w-]{16,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})/g },
    { type: "EMAIL", re: /\b[\w.%+-]+@[\w.-]+\.[A-Za-z]{2,}\b/g },
    { type: "CARD",  re: /\b(?:\d[ -]?){12,18}\d\b/g, check: passesLuhn },
    { type: "SSN",   re: /\b\d{3}-\d{2}-\d{4}\b/g },
    { type: "IP",    re: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g },
    { type: "PHONE", re: /(?:\+\d{1,3}[\s.-]?)?(?:\(\d{3}\)|\b\d{3})[\s.-]?\d{3}[\s.-]?\d{4}\b/g },
    { type: "KEY",   re: /\b[\w-]{32,}\b/g, check: looksRandom }, // generic long tokens
  ];

  // Escape characters like . or ( so a watchlist word is matched literally.
  const escapeRegex = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

  // ---------- 4. The main function ----------
  // Takes text, returns { sanitized, found: [{ type, label }, ...] }.
  function detect(text) {
    const found = [];
    let out = text;

    // Replace every match of `re` (if it passes `check`) with its label.
    const swap = (type, re, check) => {
      out = out.replace(re, (match) => {
        if (check && !check(match)) return match; // false alarm, keep it
        const label = labelFor(type, match);
        found.push({ type, label });
        return label;
      });
    };

    // Watchlist first: whole word, any letter case.
    for (const term of watchlist) {
      if (term.trim()) swap("WATCH", new RegExp(`(?<!\\w)${escapeRegex(term.trim())}(?!\\w)`, "gi"));
    }
    for (const rule of RULES) swap(rule.type, rule.re, rule.check);

    // Save the vault for this browser session (fire and forget).
    if (found.length) chrome.storage.session.set({ pgVault: vault }).catch(() => {});
    return { sanitized: out, found };
  }

  // Used later (Step 4) to swap labels back to real values on screen.
  const getLabelMap = () => vault.labelToValue;

  return { ready, detect, getLabelMap };
})();
