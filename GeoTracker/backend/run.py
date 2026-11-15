"""GeoTracker launcher: runs the backend as Administrator, hidden (no console window).

    python run.py                  # UAC prompt, then the server runs hidden in the background
    python run.py --status         # is it running? which mode?
    python run.py --stop           # clean stop (removes GeoTrench-* firewall rules)
    python run.py --foreground     # visible elevated window instead (debugging; Ctrl+C to stop)
    python run.py --foreground --reload   # dev auto-reload (each reload clears geofences)
    python run.py --no-elevate     # run in THIS terminal without admin (firewall = dry run)
    python run.py --port 8001

Logs: backend/logs/server.log (rotated at 5 MB).
Elevation uses ShellExecuteW("runas"), which always shows the Windows UAC prompt. Nothing here bypasses UAC.
The elevated process does NOT inherit $env: variables from this terminal; put settings in backend/.env.
"""
import argparse
import ctypes
import json
import os
import subprocess
import sys
import threading
import time
import traceback
import urllib.request

BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.abspath(__file__)
VENV_SCRIPTS = os.path.join(BACKEND_DIR, "venv", "Scripts")
VENV_PYTHON = os.path.join(VENV_SCRIPTS, "python.exe")
VENV_PYTHONW = os.path.join(VENV_SCRIPTS, "pythonw.exe")

LOG_DIR = os.path.join(BACKEND_DIR, "logs")
LOG_FILE = os.path.join(LOG_DIR, "server.log")
PID_FILE = os.path.join(LOG_DIR, "server.pid")
STOP_FILE = os.path.join(LOG_DIR, "server.stop")
MAX_LOG_BYTES = 5_000_000

SW_HIDE = 0
SW_SHOWNORMAL = 1
DETACHED_PROCESS = 0x00000008
CREATE_NEW_PROCESS_GROUP = 0x00000200

IS_WINDOWS = os.name == "nt"

# Local health checks must never go through an HTTP proxy.
_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


# ---------- helpers ----------

def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def python_console():
    return VENV_PYTHON if os.path.isfile(VENV_PYTHON) else sys.executable


def python_hidden():
    """pythonw.exe has no console window at all."""
    if os.path.isfile(VENV_PYTHONW):
        return VENV_PYTHONW
    candidate = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
    return candidate if os.path.isfile(candidate) else sys.executable


def get_json(host, port, path, timeout=1.0):
    try:
        with _opener.open(f"http://{host}:{port}{path}", timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", errors="replace"))
    except Exception:
        return None


def is_up(host, port):
    return get_json(host, port, "/api/health") is not None


def read_pid():
    try:
        with open(PID_FILE, encoding="utf-8") as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return None


def remove_quietly(path):
    try:
        os.remove(path)
    except OSError:
        pass


def tail(path, n=25):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return "".join(f.readlines()[-n:])
    except OSError:
        return "(no log yet)\n"


def run_elevated(exe, argv, show):
    """ShellExecuteW 'runas' -> UAC prompt. Returns True if Windows accepted (user clicked Yes)."""
    shell_execute = ctypes.windll.shell32.ShellExecuteW
    shell_execute.restype = ctypes.c_void_p  # HINSTANCE; avoid truncation on 64-bit
    rc = shell_execute(None, "runas", exe, subprocess.list2cmdline(argv), BACKEND_DIR, show)
    return (rc or 0) > 32


def print_mode(host, port):
    state = get_json(host, port, "/api/geofence/state")
    if state and isinstance(state, dict):
        print(f"  mode: {state.get('mode')}  admin: {state.get('is_admin')}")


# ---------- commands ----------

def start_hidden(args):
    if is_up(args.host, args.port):
        print(f"GeoTracker is already running at http://{args.host}:{args.port}")
        print_mode(args.host, args.port)
        return 0

    os.makedirs(LOG_DIR, exist_ok=True)
    remove_quietly(STOP_FILE)
    child = [SCRIPT, "--child", "--host", args.host, "--port", str(args.port)]

    if is_admin():
        # Already elevated: start detached, no UAC needed.
        subprocess.Popen(
            [python_hidden(), *child],
            cwd=BACKEND_DIR,
            creationflags=DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            close_fds=True,
        )
    else:
        print("Requesting Administrator rights (UAC prompt)...")
        if not run_elevated(python_hidden(), child, SW_HIDE):
            print("Elevation was cancelled or failed. Re-run, or use --no-elevate for dry-run mode.")
            return 1

    print("Starting", end="", flush=True)
    deadline = time.time() + 30
    while time.time() < deadline:
        if is_up(args.host, args.port):
            print()
            print(f"GeoTracker running in the background at http://{args.host}:{args.port}")
            print_mode(args.host, args.port)
            print(f"  logs: {LOG_FILE}")
            print("  stop: python run.py --stop")
            return 0
        print(".", end="", flush=True)
        time.sleep(0.5)

    print()
    print("Server did not come up within 30 s. Last log lines:")
    print(tail(LOG_FILE), end="")
    return 1


def stop(args):
    pid = read_pid()
    if not is_up(args.host, args.port) and pid is None:
        print("GeoTracker is not running.")
        remove_quietly(STOP_FILE)
        return 0

    os.makedirs(LOG_DIR, exist_ok=True)
    with open(STOP_FILE, "w", encoding="utf-8") as f:
        f.write("stop\n")
    print("Stopping (removing firewall rules)", end="", flush=True)

    # Wait for the server to stop answering AND for the child to finish its cleanup (it deletes the PID file last).
    deadline = time.time() + 20
    while time.time() < deadline:
        if not is_up(args.host, args.port) and not os.path.exists(PID_FILE):
            print()
            print("Stopped.")
            remove_quietly(STOP_FILE)
            return 0
        print(".", end="", flush=True)
        time.sleep(0.5)

    print()
    print("Server did not stop within 20 s.")
    if pid:
        print(f"Force-stop from an admin PowerShell:  Stop-Process -Id {pid} -Force")
        print("(Firewall rules left behind are removed automatically on the next start.)")
    print("Last log lines:")
    print(tail(LOG_FILE), end="")
    return 1


def status(args):
    if is_up(args.host, args.port):
        print(f"GeoTracker is running at http://{args.host}:{args.port} (pid {read_pid() or 'unknown'})")
        print_mode(args.host, args.port)
        print(f"  logs: {LOG_FILE}")
        return 0
    print("GeoTracker is not running.")
    if os.path.exists(PID_FILE):
        print("  (stale PID file found; it will be replaced on next start)")
    return 1


def run_child(args):
    """The hidden, elevated server process (pythonw: no console, so all output goes to the log)."""
    os.chdir(BACKEND_DIR)
    os.makedirs(LOG_DIR, exist_ok=True)
    if os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) > MAX_LOG_BYTES:
        os.replace(LOG_FILE, LOG_FILE + ".1")

    log = open(LOG_FILE, "a", encoding="utf-8", buffering=1)
    sys.stdout = log  # must happen before uvicorn configures logging (it binds to sys.stderr)
    sys.stderr = log

    remove_quietly(STOP_FILE)
    print(f"\n==== {time.strftime('%Y-%m-%d %H:%M:%S')} start pid={os.getpid()} admin={is_admin()} ====")
    with open(PID_FILE, "w", encoding="utf-8") as f:
        f.write(str(os.getpid()))

    code = 0
    try:
        import uvicorn
        server = uvicorn.Server(uvicorn.Config("server:app", host=args.host, port=args.port))

        def watch_for_stop():
            while not server.should_exit:
                if os.path.exists(STOP_FILE):
                    print("Stop requested; shutting down cleanly.")
                    server.should_exit = True  # triggers the normal lifespan shutdown (firewall cleanup)
                    return
                time.sleep(0.5)

        threading.Thread(target=watch_for_stop, daemon=True).start()
        server.run()
    except Exception:
        traceback.print_exc()
        code = 1
    finally:
        print(f"==== {time.strftime('%Y-%m-%d %H:%M:%S')} stopped ====")
        remove_quietly(STOP_FILE)
        remove_quietly(PID_FILE)  # last: run.py --stop waits for this
        log.flush()
    return code


def run_foreground(args):
    """Visible window (elevated unless --no-elevate). Ctrl+C to stop."""
    if IS_WINDOWS and not args.no_elevate and not is_admin():
        argv = [SCRIPT, "--foreground", "--host", args.host, "--port", str(args.port)]
        if args.reload:
            argv.append("--reload")
        print("Requesting Administrator rights (UAC prompt)...")
        if run_elevated(python_console(), argv, SW_SHOWNORMAL):
            print("Started an elevated window.")
            return 0
        print("Elevation was cancelled or failed.")
        return 1

    os.chdir(BACKEND_DIR)
    admin = is_admin()
    if IS_WINDOWS:
        try:
            ctypes.windll.kernel32.SetConsoleTitleW("GeoTracker (ADMIN)" if admin else "GeoTracker (NOT ELEVATED)")
        except Exception:
            pass

    code = 0
    try:
        import uvicorn
        print(f"Starting GeoTracker on http://{args.host}:{args.port} (admin: {admin})")
        uvicorn.run("server:app", host=args.host, port=args.port, reload=args.reload)
    except KeyboardInterrupt:
        pass
    except Exception:
        traceback.print_exc()  # print BEFORE pausing so the error is visible
        code = 1
    finally:
        if admin and not args.no_elevate and sys.stdin and sys.stdin.isatty():
            try:
                input("Server stopped. Press Enter to close this window...")
            except (KeyboardInterrupt, EOFError):
                pass
    return code


# ---------- entry ----------

def main():
    p = argparse.ArgumentParser(description="Start the GeoTracker backend.")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--stop", action="store_true", help="stop the background server cleanly")
    p.add_argument("--status", action="store_true", help="show whether the server is running")
    p.add_argument("--foreground", action="store_true", help="visible window instead of hidden (Ctrl+C to stop)")
    p.add_argument("--no-elevate", action="store_true", help="run in this terminal without admin (dry-run firewall)")
    p.add_argument("--reload", action="store_true", help="dev auto-reload; only with --foreground or --no-elevate")
    p.add_argument("--child", action="store_true", help=argparse.SUPPRESS)
    args = p.parse_args()

    if args.child:
        return run_child(args)
    if args.stop:
        return stop(args)
    if args.status:
        return status(args)
    if args.foreground or args.no_elevate or not IS_WINDOWS:
        return run_foreground(args)
    if args.reload:
        print("--reload needs a visible window: use  python run.py --foreground --reload")
        return 1
    return start_hidden(args)


if __name__ == "__main__":
    sys.exit(main())
