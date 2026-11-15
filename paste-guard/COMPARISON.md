# Product comparison and direction

Reviewed November 14, 2026 using PasteSecure's public [website](https://www.pastesecure.com/) and [publisher's Chrome Web Store listing](https://chromewebstore.google.com/detail/pastesecure-%E2%80%93-pii-redacti/ebolpbgeaeammpddffibagpobicfnhoc). These are advertised capabilities, not an independent audit of its implementation.

PasteSecure advertises local scanning of typed and pasted text, broad sensitive-data patterns, file scanning, per-site policies, allowlists, previews, reversible tokens, and activity reports. Local processing and site lists alone are therefore not a distinctive claim for Paste Guard. Paste Guard currently lacks typed-input protection, attachment processing, and reply restoration.

Our direction is inspectable, testable privacy for AI prompts. Version 0.6 adds a disposable Settings & tools: compare the detector's decisions before and after exceptions, simulate a destination's policy, inspect the reason behind each finding, run bundled synthetic diagnostic cases, and export a report limited to aggregate counts. These are concrete product choices, not a claim that no competitor has similar capabilities.

The lab makes no session-vault allocations and keeps its input/results only in page memory. Preview names can differ from actual session aliases. The ten synthetic checks are deliberately small and must not be presented as a precision/recall benchmark, real-world accuracy score, or security certification.

A demo: open Settings & tools, load the synthetic example, compare, add alice@example.com to Never redact in settings, and compare again. The email stays while other matches are replaced. Choose a never-redact destination to see why all matches would pass through. Run the diagnostic and export the counts-only report to inspect its exact contents.

Further candidates, not implemented here: an opt-in pre-send draft check, explicit project-specific vault isolation, and a broader published evaluation corpus. These need additional editor integration or evaluation work rather than marketing claims.
