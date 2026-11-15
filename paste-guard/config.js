// config.js
// Sites are added by the user from Settings & tools.
// (Uses "var" so this file can safely run twice in the same tab.)
var PG_SITES = [];

// Scope fallbacks to the composer so unrelated text fields are unaffected.
// ChatGPT changes its markup often, so we list the current composer form
// (data-chatgpt-composer) plus older versions as fallbacks.
var PG_INPUT_SELECTORS = [
  "#prompt-textarea",
  "form[data-chatgpt-composer] [contenteditable='true']",
  "form[data-chatgpt-composer] textarea",
  "form[data-type='unified-composer'] textarea",
  "form[data-type='unified-composer'] [contenteditable='true']",
];

// On sites the user adds from the popup we don't know the chat box's
// markup, so any multi-line text box or rich editor on the page is guarded.
var PG_GENERIC_SELECTORS = ["textarea", "[contenteditable]:not([contenteditable='false'])"];

// Turns whatever the user typed ("https://www.example.com/page", "Example.com")
// into a plain hostname ("www.example.com"). Throws a friendly error if invalid.
function pgNormalizeSite(input) {
  let text = String(input || "").trim().toLowerCase();
  if (!text) throw new Error("Enter a website, like example.com.");
  if (!/^[a-z][a-z0-9+.-]*:\/\//.test(text)) text = "https://" + text;
  let url;
  try { url = new URL(text); } catch { throw new Error("That doesn't look like a website address."); }
  if (!["http:", "https:"].includes(url.protocol)) throw new Error("Only HTTP and HTTPS websites are supported.");
  const host = url.hostname;
  if (!/^[a-z0-9.-]+$/.test(host) || !host.includes(".")) throw new Error("That doesn't look like a website address.");
  return host;
}

// Match both HTTP and HTTPS for a hostname.
var pgOriginFor = (host) => "*://" + host + "/*";

// Explicit site rules override the default protection switch. Never wins.
function pgShouldRedact(host, state) {
  if ((state.neverSites || []).includes(host)) return false;
  if ((state.sites || []).includes(host)) return true;
  return state.enabled === true;
}

// Chrome permission checks require the explicit patterns declared in manifest.
var pgOriginsFor = (host) => ["http://" + host + "/*", "https://" + host + "/*"];
