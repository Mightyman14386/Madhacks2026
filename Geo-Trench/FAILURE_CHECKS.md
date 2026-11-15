# Failure checks — 2026-11-15

Scope: Databricks incident ingestion, cached snapshots, globe geometry, frontend
failure recovery, and existing threat-classification regressions.

## Reproduced and fixed

| Failure | Evidence | Result |
| --- | --- | --- |
| Incomplete SQL results accepted as successful snapshots | Missing follow-up chunk accepted 1 of 2 rows; missing data array accepted 0 of 1 rows | Missing chunks and insufficient row counts now fail the refresh, preserving cached data |
| Unstable arcs near antipodal locations | Adjacent samples jumped 173.6 degrees for opposite endpoints and 90 degrees for nearly opposite endpoints | Stable vector interpolation; continuity tests cover exact and near antipodes and poles |
| Malformed successful API responses could reach rendering unchecked | Non-array incidents and invalid row values could throw during map/render | Validate the incident response before updating React state; browser fault injection confirms the page keeps the previous snapshot |
| Backend restart replaced cached browser data with an empty loading result | Loading response had no successful timestamp and no rows | Keep the previous snapshot, label it as reconnecting, and replace it only after a successful new snapshot |

## Passing validation

- 16 incident backend tests: OAuth SQL scope, safe authentication errors, schema
  mapping, bad coordinates, duplicates, async execution, result chunks,
  missing/incomplete results, truncation, cancellation on timeout, cache throttling,
  stale snapshots, recovery, and HTTP response status.
- 13 existing threat-classification checks, including false-positive controls and
  synthetic scenarios.
- 10 frontend unit tests: response validation, restart retention, coordinate
  validation, history, severity colors, duplicate/reversed arcs, coincident points,
  polar/antimeridian/antipodal routes, and selected routes beyond the render cap.
- Both browser suites: device-monitor regressions and incident scenarios, including
  search, details, severity filters, malformed responses, disconnected backend,
  retained stale data, empty/loading states, mobile canvas rendering, and
  filtering/selecting from 2,000 incidents.
- Production build passes.
- Real local API check: HTTP 200, state ready, 1 valid incident, no skipped rows,
  not stale. The response passes the frontend validator.

Failure injections used mocked SDK/browser responses. Live Databricks checks were
read-only; no credentials, table records, or real security controls were modified.

## Remaining limits and untested behavior

- Default snapshot limit is 2,000 rows; the globe draws at most 180 arcs, including
  the selected incident. Very dense identical routes still require selection to
  distinguish individual records.
- No timestamp or primary key is provided. Capped snapshots cannot guarantee
  newest-first ordering; content changes produce new incident IDs.
- The SQL polling timeout is not a hard end-to-end deadline. In the installed SDK,
  OAuth token acquisition uses a separate requests.post call without an explicit
  timeout. A stalled identity provider can leave the refresh worker waiting.
  This was identified in SDK source, not induced against the real service.
- Sustained load, multiple backend workers, and real permission revocation were
  not exercised. Caching is per backend process.
