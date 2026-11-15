// config.js
// The one place that lists which AI chat sites Paste Guard protects.
//
// To add a site (for example claude.ai):
//   1. Add "claude.ai" to PG_SITES below.
//   2. Add "https://claude.ai/*" to "matches" in manifest.json.
//      (Chrome reads manifest.json before any of our code runs, so the
//       manifest needs its own copy of the list.)

const PG_SITES = ["chatgpt.com", "chat.openai.com"];

// Scope fallbacks to the composer so unrelated text fields are unaffected.
// ChatGPT changes its markup often, so we list the current composer form
// (data-chatgpt-composer) plus older versions as fallbacks.
const PG_INPUT_SELECTORS = [
  "#prompt-textarea",
  "form[data-chatgpt-composer] [contenteditable='true']",
  "form[data-chatgpt-composer] textarea",
  "form[data-type='unified-composer'] textarea",
  "form[data-type='unified-composer'] [contenteditable='true']",
];
