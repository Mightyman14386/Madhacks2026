// config.js
// The one place that lists which AI chat sites Paste Guard protects.
// (Uses "var" so this file can safely run twice in the same tab.)
//
// To add a site (for example claude.ai):
//   1. Add "claude.ai" to PG_SITES below.
//   2. Add "https://claude.ai/*" to "matches" in manifest.json.
//      (Chrome reads manifest.json before any of our code runs, so the
//       manifest needs its own copy of the list.)

var PG_SITES = ["chatgpt.com", "chat.openai.com"];

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
  if (url.protocol !== "https:") throw new Error("Only https:// websites are supported.");
  const host = url.hostname;
  if (!/^[a-z0-9.-]+$/.test(host) || !host.includes(".")) throw new Error("That doesn't look like a website address.");
  return host;
}

// The Chrome permission pattern for one site, e.g. "https://example.com/*".
var pgOriginFor = (host) => `https://${host}/*`;
