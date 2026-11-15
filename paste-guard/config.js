// config.js
// The one place that lists which AI chat sites Paste Guard protects.
//
// To add a site (for example claude.ai):
//   1. Add "claude.ai" to PG_SITES below.
//   2. Add "https://claude.ai/*" to "matches" in manifest.json.
//      (Chrome reads manifest.json before any of our code runs, so the
//       manifest needs its own copy of the list.)

const PG_SITES = ["chatgpt.com", "chat.openai.com"];

// CSS selectors for a site's chat input box. We try them in order.
// "#prompt-textarea" is ChatGPT's input. The other two are generic fallbacks.
const PG_INPUT_SELECTORS = ["#prompt-textarea", "textarea", "[contenteditable='true']"];
