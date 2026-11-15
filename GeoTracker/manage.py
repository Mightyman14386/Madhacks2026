"""Run install, build, or start from the GeoTracker directory."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
ROOT = Path(__file__).resolve().parent
VENV = ROOT / "backend" / "venv"
PYTHON = VENV / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
def run(args, **kwargs):
    subprocess.run([str(x) for x in args], check=True, cwd=ROOT, **kwargs)
def main():
    parser = argparse.ArgumentParser(description="GeoTracker deployment commands")
    parser.add_argument("command", choices=["install", "build", "start"])
    args = parser.parse_args()
    if args.command == "install":
        npm = shutil.which("npm")
        if not npm:
            parser.error("Node.js and npm are required. Install Node.js before running install.")
        if not PYTHON.exists():
            run([sys.executable, "-m", "venv", VENV])
        run([PYTHON, "-m", "pip", "install", "-r", ROOT / "backend/requirements.txt"])
        run([npm, "ci", "--prefix", ROOT / "frontend", "--include=dev"])
    elif args.command == "build":
        npm = shutil.which("npm")
        if not npm:
            parser.error("npm is missing. Run install first.")
        env = dict(os.environ)
        # Production frontend always talks to the same service. Never bake a developer localhost URL.
        env["VITE_API_URL"] = ""
        run([npm, "--prefix", ROOT / "frontend", "run", "build"], env=env)
    else:
        if not PYTHON.exists() or not (ROOT / "frontend/dist/index.html").exists():
            parser.error("Run install and build before start.")
        port = os.getenv("PORT", "8000")
        if not port.isdecimal() or not 1 <= int(port) <= 65535:
            parser.error("PORT must be a number from 1 to 65535.")
        os.chdir(ROOT / "backend")
        command = [str(PYTHON), "-m", "uvicorn", "hosted:app", "--host", "0.0.0.0", "--port", port]
        if os.name == "nt":
            subprocess.run(command, check=True)
        else:
            os.execv(str(PYTHON), command)
if __name__ == "__main__":
    main()
