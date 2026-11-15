(() => {
  // Paste Guard can be injected into an already-open tab (right after a site is
  // added, or after the extension reloads). Never run twice in the same tab.
  if (globalThis.__pasteGuardLoaded) return;
  globalThis.__pasteGuardLoaded = true;

  // Built-in sites use precise chat-box selectors; sites the user added in the
  // popup use generic ones. (Chrome only injects us on sites in either list.)
  const builtIn = PG_SITES.includes(location.hostname);
  const selectors = builtIn ? PG_INPUT_SELECTORS : PG_GENERIC_SELECTORS;

  // Master on/off switch from the popup. Starts "on" so nothing slips through
  // while the real setting loads, then updates live when the switch is flipped.
  let active = true;
  const applyState = (state) => {
    if (typeof state?.enabled !== "boolean" || !Array.isArray(state.sites)) return;
    active = state.enabled && (builtIn || state.sites.includes(location.hostname));
    console.info(`[Paste Guard] ${active ? "Active" : "Paused"} on ${location.hostname}`);
  };
  chrome.runtime.sendMessage({ type: "PG_GET_STATE" }).then(applyState, () => {});
  chrome.runtime.onMessage.addListener((message, sender) => {
    if (sender.id === chrome.runtime.id && message?.type === "PG_STATE") applyState(message);
  });

  const pending = new WeakSet();
  const revisions = new WeakMap();
  let notice;

  function findChatInput(target) {
    const el = target instanceof Element ? target : target?.parentElement;
    if (!el) return null;
    for (const selector of selectors) {
      const match = el.closest(selector);
      if (match && (match instanceof HTMLTextAreaElement || match.isContentEditable)) return match;
    }
    return null;
  }

  function notify(message, error = false) {
    notice?.remove();
    const host = document.createElement("div");
    notice = host;
    host.id = "paste-guard-notice";
    host.style.cssText = "position:fixed;bottom:24px;right:24px;z-index:2147483647;max-width:380px";
    const root = host.attachShadow({ mode: "closed" });
    const box = document.createElement("div");
    box.style.cssText = `font:14px/1.5 system-ui;color:white;background:${error ? "#792525" : "#163d35"};padding:14px 18px;border-radius:12px;box-shadow:0 4px 20px #0005`;
    box.setAttribute("role", error ? "alert" : "status");
    box.textContent = `Paste Guard: ${message} `;
    const dismiss = document.createElement("button");
    dismiss.textContent = "Dismiss";
    dismiss.style.cssText = "background:transparent;color:inherit;border:1px solid currentColor;border-radius:4px;cursor:pointer;margin-left:8px";
    dismiss.addEventListener("click", () => host.remove());
    box.append(dismiss);
    root.append(box);
    (document.body || document.documentElement).append(host);
    if (!error) setTimeout(() => host.remove(), 5000);
  }

  function snapshot(input) {
    const revision = revisions.get(input) || 0;
    if (input instanceof HTMLTextAreaElement) {
      if (input.disabled || input.readOnly) throw new Error("This editor is read-only.");
      return { value: input.value, start: input.selectionStart, end: input.selectionEnd, revision };
    }
    const selection = window.getSelection();
    if (!selection?.rangeCount) throw new Error("Select a position in the chat editor and paste again.");
    const range = selection.getRangeAt(0);
    if (!input.contains(range.startContainer) || !input.contains(range.endContainer)) throw new Error("Select a position inside the chat editor.");
    return { html: input.innerHTML, range: range.cloneRange(), revision };
  }

  function unchanged(input, saved) {
    if (!input.isConnected || !input.contains(document.activeElement)
        || (revisions.get(input) || 0) !== saved.revision) return false;
    if (input instanceof HTMLTextAreaElement) {
      return !input.disabled && !input.readOnly && input.value === saved.value
        && input.selectionStart === saved.start && input.selectionEnd === saved.end;
    }
    const selection = window.getSelection();
    if (!input.isContentEditable || input.innerHTML !== saved.html || !selection?.rangeCount) return false;
    const range = selection.getRangeAt(0);
    return range.startContainer === saved.range.startContainer && range.startOffset === saved.range.startOffset
      && range.endContainer === saved.range.endContainer && range.endOffset === saved.range.endOffset;
  }

  function insert(input, saved, text) {
    // Chromium's editing command updates contenteditable editors and preserves
    // undo. Direct innerHTML/Range mutation can desynchronize framework state.
    // insertText turns newlines into paragraphs in rich editors. Escaped HTML
    // with explicit breaks preserves the clipboard's line breaks instead.
    if (!(input instanceof HTMLTextAreaElement) && /[\r\n]/.test(text)) {
      const html = text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
        .replace(/\r\n?/g, "\n").replace(/\n/g, "<br>");
      if (document.execCommand("insertHTML", false, html)) return;
      throw new Error("This editor could not accept the sanitized paste. Try again after reloading the page.");
    }
    if (document.execCommand("insertText", false, text)) return;
    if (!(input instanceof HTMLTextAreaElement)) throw new Error("This editor could not accept the sanitized paste. Try again after reloading the page.");
    const value = saved.value.slice(0, saved.start) + text + saved.value.slice(saved.end);
    const setter = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value").set;
    setter.call(input, value);
    input.setSelectionRange(saved.start + text.length, saved.start + text.length);
    input.dispatchEvent(new InputEvent("input", { bubbles: true, composed: true, inputType: "insertText", data: text }));
  }

  async function sanitize(text) {
    let timeout;
    try {
      return await Promise.race([
        chrome.runtime.sendMessage({ type: "PG_SANITIZE", text }),
        new Promise((_, reject) => { timeout = setTimeout(() => reject(new Error("Detection timed out. Your paste was blocked; please try again.")), 15000); }),
      ]);
    } finally { clearTimeout(timeout); }
  }

  document.addEventListener("input", (event) => {
    const input = findChatInput(event.target);
    if (input) revisions.set(input, (revisions.get(input) || 0) + 1);
  }, true);

  window.addEventListener("paste", (event) => {
    if (!active) return; // switched off: let the site handle the paste normally
    // The extension was reloaded and this copy is stale. Step aside so the
    // freshly injected copy handles the paste instead of showing an error.
    if (!chrome.runtime?.id) return;
    const input = findChatInput(event.target);
    if (!input || !event.clipboardData?.types.includes("text/plain")) return;
    // Must happen synchronously, BEFORE waiting on the worker. Neither the
    // browser nor the site's paste handler should receive the original paste.
    event.preventDefault();
    event.stopImmediatePropagation();
    if (pending.has(input)) {
      notify("A paste is already being checked. Wait for it to finish.", true);
      return;
    }
    const text = event.clipboardData.getData("text/plain");
    let saved;
    try { saved = snapshot(input); }
    catch (error) { notify(error.message, true); return; }
    pending.add(input);
    void (async () => {
      try {
        const result = await sanitize(text);
        if (!result?.ok || typeof result.sanitized !== "string") throw new Error(result?.error || "Could not check the paste. Reload the extension and this page, then try again.");
        if (!unchanged(input, saved)) throw new Error("The editor or selection changed while checking. Your paste was cancelled; paste again at the desired position.");
        insert(input, saved, result.sanitized);
        if (result.found.length) notify(`Replaced ${result.found.length} sensitive item${result.found.length === 1 ? "" : "s"}.`);
      } catch (error) {
        notify(`Paste blocked. ${error.message || "Please reload the page and try again."}`, true);
      } finally { pending.delete(input); }
    })();
  }, true);
})();
