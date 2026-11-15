# Databricks incident feed

The main globe reads workspace.default.geospatial_incidents through the Python
Databricks SDK. Browser code only calls the local backend; it receives neither
Databricks credentials nor OAuth tokens.

## Configure

The local, Git-ignored backend/.env has the supplied workspace and placeholders:

~~~dotenv
DATABRICKS_HOST=https://dbc-84f3eead-a719.cloud.databricks.com
DATABRICKS_CLIENT_ID=<service-principal-client-id>
# DATABRICKS_CLIENT_SECRET=<service-principal-secret>
DATABRICKS_WAREHOUSE_ID=f281300984d67642
~~~

Replace the client ID, remove the leading # on the secret line, and replace the
secret placeholder. Use a Databricks OAuth service-principal secret. Keep the real
values in .env; do not add VITE_ prefixes or put credentials in frontend files.
Restart the backend after changing environment values.

The service principal needs access to the workspace, permission to use the SQL
warehouse, and permission to read the table (including its catalog and schema).
The incident SDK client explicitly requests the **sql** OAuth scope, rather than
its default all-apis scope. This supports secrets restricted to SQL access.
The SDK uses unified authentication. To use a PAT or CLI profile instead, remove
the placeholder client ID and secret lines and configure DATABRICKS_TOKEN or
DATABRICKS_CONFIG_PROFILE. Configure one authentication method.

Install and run from the backend directory:

~~~powershell
.\venv\Scripts\python.exe -m pip install -r requirements.txt
.\venv\Scripts\python.exe -m uvicorn server:app --host 127.0.0.1 --port 8000
~~~

## Query and API behavior

GET /api/incidents starts a background query on first access and serves cached
snapshots while refreshing. Browser polling (3 seconds) does not submit a new SQL
query on each request. Query refresh defaults to 30 seconds while clients poll.

The query selects latitude_src, longitude_src, latitude_dest,
longitude_dest, severity, description, and ip. It polls asynchronous SQL
execution and follows inline result chunks. It does not modify the table.

- DATABRICKS_MAX_ROWS: 2,000 by default; maximum 10,000. One extra row detects truncation.
- DATABRICKS_QUERY_TIMEOUT: 45 seconds by default; bounds polling, with individual SDK request/retry timeouts.
- DATABRICKS_REFRESH_SECONDS: 30 by default, minimum 5.
- Result payload limit: 4 MiB. Oversized/failed results are reported as errors.
- States: loading, refreshing, ready, error.
- fetched_at is the successful snapshot time, not the incident occurrence time.
- Initial errors return HTTP 503. Refresh failures retain the previous snapshot
  with stale: true, a generic message, and HTTP 200.
- Invalid/missing coordinates are skipped and counted. Unknown severities remain
  visible in gray. Required columns missing from a result fail the query.
- Identical rows are retained. Content-hash IDs plus an occurrence suffix provide
  stable selection across reordered responses without inventing a primary key.
- No timestamp or primary key is supplied, so the capped query does not claim to
  return the newest records. Add an ordering column if newest-first is required.

The UI shows low (mint), medium (amber), high (peach), and critical (violet).
Every arc uses its row's source and destination and has glowing endpoints.
Coincident routes, including reversed routes, receive stable offsets bounded to
about two degrees laterally and a small elevation difference. Identical endpoints
use a small loop. With many coincident incidents, select one to highlight it.

At most 180 arcs are drawn for rendering performance; selecting any incident in
the list includes its arc in that limit. The list and filters cover all loaded
incidents. The associated IP is displayed as supplied, without assuming which
endpoint it belongs to. Device monitoring remains available under **Device traffic**.

## Verify

~~~powershell
# Backend, from backend/
.\venv\Scripts\python.exe -m unittest test_incidents -v
# Frontend, from frontend/
npm test
npm run build
# With npm run dev running at http://localhost:5173:
npm run test:browser
~~~

Tests use SDK response models and mocked warehouse results, including chunking,
timeouts, invalid coordinates, duplicate rows, retained stale data, and browser
failure states. A live warehouse query additionally requires valid credentials.

Authentication reference: https://databricks-sdk-py.readthedocs.io/en/latest/authentication.html
