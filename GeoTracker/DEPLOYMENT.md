# Run GeoTracker as one service

From the GeoTracker directory, with Python 3.11+ and Node.js 22 installed:

~~~sh
python manage.py install
python manage.py build
python manage.py start
~~~

On Linux use python3 if python is not available. Install prepares backend/venv and
installs frontend packages from the lockfile. Build creates frontend/dist. Start
serves both the production website and read-only API at http://localhost:8000.
PORT overrides 8000. Start does not use the Windows administrator launcher.

## Render

Create a native Python Web Service from this repository:
- Language / Runtime: Python 3
- Root Directory: GeoTracker
- Health Check Path: /api/health
- Node version: 22 (NODE_VERSION environment variable)

Build Command:

~~~sh
pip install -r backend/requirements.txt && npm ci --prefix frontend --include=dev && python manage.py build
~~~

Start Command:

~~~sh
python -m uvicorn hosted:app --app-dir backend --host 0.0.0.0 --port $PORT
~~~

The build command installs Python requirements into the native runtime, installs
frontend dependencies from the lockfile, and builds production assets. The start
command uses that same Python environment and serves the website and API together.
No separate install-command field or container is needed. The checked-in
.python-version selects Python 3.11; remove any conflicting PYTHON_VERSION override.

Alternatively create a Blueprint and select GeoTracker/render.yaml as its path.
The blueprint's rootDir is relative to the repository root.

Add DATABRICKS_HOST, DATABRICKS_CLIENT_ID and DATABRICKS_CLIENT_SECRET as Render
environment variables; do not upload backend/.env. The warehouse ID defaults to
f281300984d67642. The client must be allowed the sql OAuth scope and have read
access to workspace.default.geospatial_incidents.

The frontend uses same-origin /api requests in production, so neither a localhost
API URL nor a public VITE_API_URL is needed. Credentials stay on the server.

## Hosted versus local

The hosted service supports database incidents and the educational/demo UI.
It cannot monitor a visitor's device or change their firewall. It does not collect
Render's own process connections, export them, run local enforcement jobs, or expose
quarantine/control endpoints. Its API intentionally has no administrative actions.
Databricks data returned by this website is public to anyone who can visit the
deployment. Restrict access at the hosting layer if the records are private.

Local Windows monitoring remains available through backend/run.py and the Vite
dev server. The original workflow is unchanged. No SQLite persistence or disk is
needed by the hosted read-only service.

Reference: https://render.com/docs/deploy-fastapi
