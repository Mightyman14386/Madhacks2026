# Bundled name vocabulary

Generated for Paste Guard on 2026-11-15. This is a deduplicated vocabulary of given-name spellings, not a list of identifiable people. The bundle contains no sex labels, birth years, counts, countries, addresses, or other per-record metadata.

## International names

Source: https://github.com/solvenium/names-dataset
Pinned revision: 6adf76b5b36fb7a3f498c166f02f0b51afcdf69c
Inputs: dataset/Female_given_names.txt and dataset/Male_given_names.txt
Copyright (c) 2019 Solvenium. Repository license: MIT; full notice retained in names-solvenium.LICENSE.
The repository attributes its lists to the Wiktionary Names Appendix: https://en.wiktionary.org/wiki/Appendix:Names
Wiktionary contributors are credited as the underlying source; no definitions, meanings, or other descriptive prose are included.
Names and language coverage reflect the upstream lists, not a comprehensive worldwide census.

## SSA national data

Source: https://www.ssa.gov/oact/babynames/names.zip
Description: https://www.ssa.gov/oact/babynames/background.html
Catalog/license: https://catalog.data.gov/dataset/baby-names-from-social-security-card-applications-national-data
The catalog lists CC0 1.0: https://creativecommons.org/publicdomain/zero/1.0/
Source archive SHA-256 is pinned in scripts/name-sources.json.
Covers US birth registrations from 1880 onward, including names used by immigrant families. It does not imply worldwide coverage. The source suppresses rare name/year groups and includes some non-name entries; do not treat it as a validated identity directory.

## Modifications

The builder normalizes NFC Unicode and case, removes whitespace-containing entries, punctuation outside letters/apostrophes/hyphens, strings shorter than three characters or longer than 60 code units, and duplicates. Source sex categories are combined solely as vocabulary, never used to infer a person's sex or gender.

scripts/name-additions.json includes user-requested spellings absent from these snapshots: Stavan. This entry is a local addition, not an upstream dataset claim.

Full source URLs, hashes, accepted-row counts, and final bundle hash are in names.metadata.json. The runtime needs only names.js; ship this attribution file and names-solvenium.LICENSE alongside it. Raw archives are build-only caches under ignored test-results/. No network request is made for detection.
