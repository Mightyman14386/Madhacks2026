// content.js
// Runs inside the chat page. Step 1: notice pastes into the chat box and log them.

(() => {
  // Safety check: only run on the sites listed in config.js.
  const host = location.hostname;
  const allowed = PG_SITES.some((site) => host === site || host.endsWith("." + site));
  if (!allowed) return;

  // Given the element that received the paste, return the chat input box
  // it belongs to, or null if the paste happened somewhere else.
  function findChatInput(target) {
    // Sometimes the target is a text node, so step up to its parent element.
    const el = target instanceof Element ? target : target && target.parentElement;
    if (!el) return null;

    for (const selector of PG_INPUT_SELECTORS) {
      const match = el.closest(selector);
      if (match) return match;
    }
    return null;
  }

  // Listen in the "capture" phase (the `true` below). That means we see the
  // paste BEFORE the site's own editor does, so later we can change it first.
  document.addEventListener(
    "paste",
    (event) => {
      const input = findChatInput(event.target);
      if (!input) return; // Not the chat box, so ignore it.

      const text = event.clipboardData ? event.clipboardData.getData("text/plain") : "";
      console.log("[Paste Guard] Paste into chat input:", JSON.stringify(text));

      // Step 2: run the detector and log what it WOULD do.
      // The paste still goes through unchanged (swapping comes in Step 3).
      const result = PasteGuard.detect(text);
      console.log("[Paste Guard] Sanitized:", result.sanitized);
      console.table(result.found);
    },
    true
  );

  console.log("[Paste Guard] Loaded on", host);
})();
