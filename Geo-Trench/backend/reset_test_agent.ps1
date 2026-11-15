param([switch]$Quarantine)

$api  = "http://127.0.0.1:8000"
$name = "test_agent"
$exe  = Join-Path $env:TEMP "$name.exe"
$out  = Join-Path $env:TEMP "${name}_dl.tmp"
$urls = @(
    "https://fsn1-speed.hetzner.com/100MB.bin",
    "https://proof.ovh.net/files/100Mb.dat",
    "https://speedtest.tele2.net/100MB.zip"
)

# ---- 1. Clean slate ----
Get-Process $name -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
Remove-Item $exe, $out -Force -ErrorAction SilentlyContinue
Write-Host "[1] Cleaned up old $name process and files" -ForegroundColor Cyan

# ---- 2. Check the server is up ----
try { $null = irm "$api/api/health" -TimeoutSec 5 }
catch { Write-Host "Server not reachable at $api. Start uvicorn first." -ForegroundColor Red; return }

# ---- 3. Recreate and launch, trying each URL until one shows up in the API ----
$c = $null
foreach ($url in $urls) {
    Get-Process $name -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Remove-Item $exe, $out -Force -ErrorAction SilentlyContinue
    Copy-Item "$env:SystemRoot\System32\curl.exe" $exe -Force

    Write-Host "[2] Launching against $url" -ForegroundColor Cyan
    $p = Start-Process -FilePath $exe -WindowStyle Hidden -PassThru -ArgumentList `
         '-s','-o',$out,'--limit-rate','2k','--max-time','300',$url
    Start-Sleep -Seconds 4

    if ($p.HasExited) {
        Write-Host "    Exited immediately (exit code $($p.ExitCode)). Trying next URL." -ForegroundColor Yellow
        continue
    }

    # Poll the API for up to ~16 seconds
    for ($i = 0; $i -lt 8 -and -not $c; $i++) {
        $r = irm "$api/api/connections"
        $c = $r.connections | Where-Object { $_.process_name -eq "$name.exe" } | Select-Object -First 1
        if (-not $c) { Start-Sleep -Seconds 2 }
    }
    if ($c) { break }

    $any = $r.anycast | Where-Object { $_.process_name -eq "$name.exe" }
    if ($any) { Write-Host "    Host is anycast/CDN (not placeable on globe). Trying next URL." -ForegroundColor Yellow }
    else      { Write-Host "    Not listed by the API. Trying next URL." -ForegroundColor Yellow }
}

if (-not $c) {
    Write-Host "Could not get $name.exe into /api/connections with any URL." -ForegroundColor Red
    return
}

Write-Host "[3] Found in API:" -ForegroundColor Green
$c | Select-Object id, process_name, remote_ip, country_code, status, severity, is_protected | Format-List

if (-not $Quarantine) {
    Write-Host "Ready. Run again with -Quarantine to quarantine it, or use id $($c.id)." -ForegroundColor Green
    return
}

# ---- 4. Quarantine and verify ----
Write-Host "[4] POST /api/quarantine" -ForegroundColor Cyan
try {
    $res = irm -Method Post -Uri "$api/api/quarantine" -ContentType "application/json" `
           -Body (@{conn_id = $c.id} | ConvertTo-Json)
    $res | ConvertTo-Json
} catch {
    Write-Host "Server returned an error:" -ForegroundColor Yellow
    Write-Host $_.ErrorDetails.Message
}

Start-Sleep -Seconds 1
Write-Host "`n--- Verification ---" -ForegroundColor Cyan
"Process still running: " + [bool](Get-Process $name -ErrorAction SilentlyContinue)
"File still in TEMP:    " + (Test-Path $exe)
"Quarantine folder:"
Get-ChildItem "C:\GeoTrench\quarantine" -ErrorAction SilentlyContinue | Select-Object Name, Length
Write-Host "`nManifest list:"
irm "$api/api/quarantine/list" | ConvertTo-Json -Depth 4
Remove-Item $out -Force -ErrorAction SilentlyContinue