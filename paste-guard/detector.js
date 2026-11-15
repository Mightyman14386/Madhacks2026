// Pure local detection. Offsets always refer to the ORIGINAL text; the worker
// resolves matches and allocates aliases before rendering the result once.
const PasteGuard = (() => {
  const WATCH_TYPES = new Set(["PERSON", "ORG", "CONFIDENTIAL", "WATCH"]);
  const escapeRegex = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const word = /[\p{L}\p{N}\p{M}_]/u;

  function normalizeWatchlist(value, strict = false) {
    if (!Array.isArray(value)) {
      if (strict) throw new Error("The watchlist must be a list.");
      return [];
    }
    if (value.length > 500) throw new Error("Use at most 500 watchlist entries.");
    const result = [], seen = new Set();
    for (const item of value) {
      const entry = typeof item === "string" ? { text: item, type: "WATCH" } : item;
      if (!entry || typeof entry.text !== "string" || !WATCH_TYPES.has(entry.type)
          || !entry.text.trim() || entry.text.trim().length > 200) {
        if (strict) throw new Error("Each entry needs a term (1–200 characters) and a valid category.");
        continue;
      }
      const text = entry.text.trim(), caseSensitive = entry.caseSensitive === true;
      const key = `${caseSensitive}:${caseSensitive ? text : text.toLowerCase()}`;
      if (seen.has(key)) {
        if (strict) throw new Error("Remove duplicate watchlist terms.");
        continue;
      }
      seen.add(key);
      result.push({ text, type: entry.type, caseSensitive });
    }
    return result;
  }

  function passesLuhn(value) {
    const digits = value.replace(/\D/g, "");
    if (digits.length < 13 || digits.length > 19 || /^(\d)\1+$/.test(digits)) return false;
    let sum = 0;
    for (let i = 0; i < digits.length; i++) {
      let digit = Number(digits[digits.length - 1 - i]);
      if (i % 2) { digit *= 2; if (digit > 9) digit -= 9; }
      sum += digit;
    }
    return sum % 10 === 0;
  }

  const RULES = [
    { type: "JWT", re: /(?<![\w-])eyJ[\w-]+\.eyJ[\w-]+\.[\w-]+(?![\w-])/g },
    { type: "KEY", re: /(?<![\w-])(?:sk-[\w-]{16,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})(?![\w-])/g },
    { type: "EMAIL", re: /(?<![\w.%+@-])[\w.%+-]+@[\w-]+(?:\.[\w-]+)*\.[A-Za-z]{2,}(?![\w@-])/g },
    // Require common card grouping with a consistent separator. Arbitrary
    // digit/separator runs can accidentally concatenate two unrelated SSNs.
    { type: "CARD", re: /(?<![\w-])(?:\d{4}([ -])\d{4}\1\d{4}\1\d{4}(?:\1\d{1,3})?|\d{4}([ -])\d{6}\2\d{4,5}|\d{13,19})(?![\w-])/g, check: passesLuhn },
    { type: "SSN", re: /(?<!\w)\d{3}-\d{2}-\d{4}(?!\w)/g,
      check: (s) => !/^(000|666|9\d\d)-/.test(s) && s.slice(4, 6) !== "00" && s.slice(7) !== "0000" },
    { type: "IP", re: /(?<![\w.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\w|\.\d)/g },
    { type: "PHONE", re: /(?<![\w+])(?:\+\d{1,3}[ .-]?)?(?:\([2-9]\d{2}\)|[2-9]\d{2})[ .-]?[2-9]\d{2}[ .-]?\d{4}(?!\w)/g },
  ];

  function collect(text, watchlist = []) {
    if (typeof text !== "string" || text.length > 100000) throw new Error("Paste up to 100,000 characters at a time.");
    const candidates = [];
    const add = (start, end, type, source, rank) => {
      if (start >= 0 && end > start && end <= text.length) candidates.push({ start, end, type, source, rank, value: text.slice(start, end) });
    };
    RULES.forEach((rule, i) => {
      for (const match of text.matchAll(rule.re)) {
        if (!rule.check || rule.check(match[0])) add(match.index, match.index + match[0].length, rule.type, "pattern", 400 - i);
      }
    });
    // Mixed case alone is not evidence of a secret. Unprefixed tokens require
    // explicit context instead of replacing ordinary long identifiers.
    const contextualKey = /\b(?:api[_ -]?key|access[_ -]?token|client[_ -]?secret|password)\s*[:=]\s*["']?([A-Za-z0-9_./+=-]{12,})/gi;
    for (const match of text.matchAll(contextualKey)) {
      const start = match.index + match[0].lastIndexOf(match[1]);
      add(start, start + match[1].length, "KEY", "pattern", 390);
    }
    for (const entry of normalizeWatchlist(watchlist)) {
      const re = new RegExp(escapeRegex(entry.text), entry.caseSensitive ? "gu" : "giu");
      for (const match of text.matchAll(re)) {
        const start = match.index, end = start + match[0].length;
        const before = Array.from(text.slice(Math.max(0, start - 2), start)).at(-1) || "";
        const after = Array.from(text.slice(end, end + 2))[0] || "";
        if ((word.test(Array.from(entry.text)[0]) && word.test(before))
            || (word.test(Array.from(entry.text).at(-1)) && word.test(after))) continue;
        add(start, end, entry.type, "watchlist", 200);
      }
    }
    if (typeof nlp !== "function") throw new Error("Local name detection is unavailable. Reload Paste Guard.");
    // Term offsets preserve surrounding quotes, punctuation and whitespace.
    for (const person of nlp(text).people().json({ offset: true })) {
      const first = person.terms[0], last = person.terms.at(-1);
      if (first?.offset && last?.offset) add(first.offset.start, last.offset.start + last.offset.length, "PERSON", "name", 100);
    }
    // Structured secrets beat overlapping words. Otherwise longest wins, then
    // explicit watchlist classifications beat inferred names for equal spans.
    candidates.sort((a, b) => {
      const aStructured = a.rank >= 300, bStructured = b.rank >= 300;
      if (aStructured !== bStructured) return aStructured ? -1 : 1;
      if (aStructured) return (b.end - b.start) - (a.end - a.start) || b.rank - a.rank;
      return (b.end - b.start) - (a.end - a.start) || b.rank - a.rank || a.start - b.start;
    });
    const selected = [];
    for (const match of candidates) {
      if (!selected.some((other) => match.start < other.end && other.start < match.end)) selected.push(match);
    }
    if (selected.length > 2000) throw new Error("Too many sensitive items. Paste a smaller section.");
    return selected.sort((a, b) => a.start - b.start).map(({ rank, ...match }) => match);
  }

  function render(text, matches, replacements) {
    let cursor = 0;
    const parts = [];
    matches.forEach((match, i) => {
      parts.push(text.slice(cursor, match.start), replacements[i]);
      cursor = match.end;
    });
    parts.push(text.slice(cursor));
    return parts.join("");
  }
  return { collect, render, normalizeWatchlist };
})();
