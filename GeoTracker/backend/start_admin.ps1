# Starts the GeoTracker backend in an elevated (Administrator) PowerShell window.
# Usage: right-click > "Run with PowerShell", or:  powershell -ExecutionPolicy Bypass -File .\start_admin.ps1
# Windows shows a UAC prompt; click Yes. Nothing here bypasses UAC.

$ErrorActionPreference = "Stop"
$backend = $PSScriptRoot
$python  = Join-Path $backend "venv\Scripts\python.exe"
$port    = 8000

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "Requesting Administrator rights (UAC prompt)..."
    try {
        Start-Process powershell.exe -Verb RunAs -ArgumentList @(
            "-NoExit", "-ExecutionPolicy", "Bypass", "-File", "`"$PSCommandPath`""
        )
    } catch {
        Write-Host "Elevation was cancelled. The backend was not started." -ForegroundColor Yellow
    }
    exit
}

if (-not (Test-Path $python)) {
    Write-Host "venv not found at $python. Create it first (see TESTING.md)." -ForegroundColor Red
    exit 1
}

$inUse = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
if ($inUse) {
    Write-Host "Port $port is already in use (PID $($inUse[0].OwningProcess)). Stop that server first." -ForegroundColor Red
    exit 1
}

Set-Location $backend
$Host.UI.RawUI.WindowTitle = "GeoTracker backend (Administrator)"
Write-Host "Starting GeoTracker backend as Administrator on http://127.0.0.1:$port ..." -ForegroundColor Green
& $python -m uvicorn server:app --host 127.0.0.1 --port $port
