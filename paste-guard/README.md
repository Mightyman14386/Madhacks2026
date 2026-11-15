# Paste Guard

A Manifest V3 Chrome extension that replaces detected sensitive text when pasting into the ChatGPT composer. Detection and alias allocation run entirely on-device: no API keys, external inference service, CDN, or runtime downloads.

## Run

1. Open `chrome://extensions`, enable **Developer mode**, and choose **Load unpacked**.
2. Select this `paste-guard` directory. For an existing installation, click **Reload**.
3. Reload existing ChatGPT tabs so they receive the new paste handler.
4. Paste into the chat composer. For example, `Alice Smith: alice@example.com` becomes `Alex Morgan: [EMAIL_1]` in a fresh session.
5. Click the toolbar icon to open the popup: a default protection switch (Always On sites remain protected), a session counter, and **Always On**. HTTP/HTTPS sites follow the switch by default; add a hostname to Always On to keep protection enabled there even when the switch is off. Removing a site restores the default switch behavior.
6. Open the extension's **Details → Extension options** (or **Watchlist & settings** in the popup) to add custom terms with categories: Person, Organization, Confidential phrase, or Generic term.

The bundled `vendor/compromise.js` is included, so loading the extension does not require npm. Aliases depend on prior detections and are reused for the same value during the session. People receive readable names, organizations receive `Example Company N`, and structured secrets receive category labels. If an existing alias also appears literally in a paste that needs that alias, the paste is blocked with an explanation rather than introducing an ambiguous mapping.

## How it works

- `config.js` defines exact supported hostnames and composer selectors. Keep manifest matches and this list in sync when adding a site.
- `content.js` intercepts plain-text paste at window capture, cancels the native paste synchronously, and sends the text to the extension worker. It inserts only the returned sanitized text, preserving the selection and undo where Chromium's editor supports it. Editing or moving the selection while detection is pending cancels insertion. Failures show a notice and never fall back to the raw paste.
- `background.js` serializes initialization, configuration changes, allocation, and persistence. All tabs use the same authority, and worker restarts reload the saved vault. No successful response is sent until its mappings are saved.
- `detector.js` collects original-text spans using structured regex rules, a typed watchlist, and bundled Compromise 14.20.0 English person-name detection. Complete structured secrets win over overlapping words. Other matches prefer the longest phrase, with explicit classifications winning equal-span ties. Rendering happens once, so replacements cannot be redetected or nested.
- `options.html` / `options.js` provide local watchlist configuration. Settings changes apply to subsequent pastes without reloading tabs.

## Data and limitations

- Original values and aliases live in extension `storage.session`, restricted to trusted extension contexts. They are not persisted to disk by this application. Closing the browser or reloading/updating/disabling the extension can reset the session. There is no automatic restoration of model responses yet.
- Explicitly configured watchlist terms persist in `storage.local` on this device. On first use, old synced watchlist terms are migrated locally, then the extension removes its synced watchlist key. Existing local settings take precedence. The obsolete v0.2 vault is discarded because its per-tab mappings can conflict.
- Raw pastes and mappings are not logged. Only sanitized text is inserted into the page. Typed input, file/image attachments, other editors, and text already in a draft are outside the paste handler's coverage.
- Name recognition is heuristic and English-oriented, not a guarantee of anonymization. Add unusual names and confidential phrases to the watchlist and review the resulting text. Organizations require watchlist entries; they are not automatically inferred. Person-name variants such as a surname alone and a full name are separate values.
- Structured detection covers common email, North American-style phone, IPv4, SSN, card grouping, JWT, and key formats. Card checks validate formatting/checksum, not whether a card exists. Unknown tokens require recognizable assignment context such as `api_key=...`; ordinary mixed-case identifiers are not treated as secrets. Some formats and arbitrary passwords will not be recognized.
- Each paste is limited to 100,000 characters and 2,000 selected matches; watchlists are limited to 500 terms of 200 characters each. Processing timeouts and storage failures block the paste with a visible message.
- Rich editor integration uses Chromium's legacy editing commands to retain native editing/undo behavior. The actual unpacked extension is tested against local textarea/contenteditable fixtures at the supported origin, not a logged-in live ChatGPT editor. Future site/editor changes may require updating selectors or insertion handling.

## Development and verification

Use a current Node.js release (the tests use `node:test`).

```sh
npm ci
npm run vendor
npm test
npx playwright install chromium
npm run test:browser
```

`npm run vendor` copies the pinned dependency's browser bundle and MIT license into `vendor/`. Commit these files when updating the dependency. Playwright is a development-only dependency. Neither it nor `node_modules` is loaded by the extension.

Unit tests use the actual bundled detector with simulated extension storage to exercise initialization, concurrent requests, worker restarts, overlap resolution, alias collisions, malformed configuration, and persistence failures. Browser tests load the actual unpacked MV3 extension in an isolated Chromium profile, route the supported origin to local fixtures, and exercise trusted clipboard pastes, selection replacement, undo, rich text, cancellation, and the settings page. They do not access a ChatGPT account or send a chat message.

For distribution, include only the manifest, runtime JavaScript, options HTML/CSS, and `vendor/` bundle/license; exclude dependencies, tests, and test browser profiles.

## Website rules and phrase exceptions

The settings page contains Always redact and Never redact lists for websites and phrases. Website changes save immediately. Phrase changes are saved together with Save phrase rules. Existing custom phrases and added websites are retained.

Website rules match exact HTTP/HTTPS hostnames (www and subdomains are separate). Ordinary HTTP and HTTPS websites are protected by default when the switch is on. Never-redact sites override added sites; Always On sites remain protected even when the default protection switch is off. Removing a site override restores the default switch behavior.

Never-redact phrases use literal, whole-word matching and an optional case-sensitive setting. They override automatic detection and manual redaction rules. Any complete detection that overlaps an exception is preserved, including a full email or full name when only part matches the exception. This avoids rewriting a phrase the user explicitly asked to keep. These exceptions persist locally alongside the watchlist.

## Settings & tools (v0.6)

Open Settings & tools from the toolbar popup or settings navigation. Compare detection before and after your phrase exceptions, optionally simulate a destination's site policy, and inspect each match's source and reason. The lab uses temporary aliases without writing to the session vault. Input/results stay in the page and can be cleared; they are not saved. Changes to input, destination, or rules invalidate the previous preview.

Run synthetic checks to exercise ten bundled examples against the detector without custom rules. This is a diagnostic, not an accuracy benchmark. Export counts only downloads a JSON report with category totals and extension version, excluding originals, aliases, phrases, and destination. Copy this preview is an explicit clipboard action. Website pages cannot call the extension-only lab API.

See COMPARISON.md for the public-source product comparison and rationale.

## Unified settings (v0.6.3)

Open Settings & tools from the popup or gear icon. Website rules, phrase rules, text preview, and synthetic detection checks now share one scrolling page, with sidebar links to each section. Save phrase changes before running a preview. Existing lab.html bookmarks redirect to options.html#preview. Popup cards now have consistent gaps and padding.

## Always On precedence

Never-redact websites override all other website rules. Explicit Always On sites (the stored sites list) override the default protection switch, so switching protection off does not pause these sites. Unlisted websites follow the default protection switch. The content script, background worker, and text preview use the same policy helper. Phrase exceptions continue to apply on Always On sites.

## Default website protection (v0.6.5)

On ordinary HTTP/HTTPS web pages, Never redact wins, then Always On, then the protection switch. The manifest requests access to HTTP/HTTPS pages and injects the handler at document start, including pages on neither list. Restricted browser pages, extension pages, unsupported editor implementations, and sites where Chrome withholds access are outside this coverage. Existing tabs should be refreshed after updating. Textareas and contenteditable editors are supported; single-line fields, typing, and uploads are unchanged.

## Website-list regression checks (v0.6.6)

Run npm run test:sites to test adding through the real popup and settings page in an isolated Chromium profile using the shipping manifest. The scenarios exercise full-URL normalization, duplicates, invalid input, persistence, moving between override lists, removal/re-addition, preview permission checks, and real clipboard redaction on newly added sites with protection off. No Chrome permission APIs or policy storage are mocked in this suite.

Website rules are local settings, so saving them no longer requests optional host permissions. The manifest already declares HTTP/HTTPS access; Chrome site-access settings still control whether scripts can run. Previews check explicit HTTP and HTTPS permission patterns to match the manifest.
