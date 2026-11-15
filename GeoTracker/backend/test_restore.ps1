<#
  test_restore.ps1 - GeoTracker step 7E verification (quarantine restore)

  Put this file in backend\ next to reset_test_agent.ps1.
  The backend must already be running (admin terminal) with the 7E changes applied.
  Run from a SECOND PowerShell window, inside backend\:

      Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
      .\test_restore.ps1

  Options:
      -Base http://127.0.0.1:8000           API base URL
      -TargetPath "$env:TEMP\test_agent.exe" where the test agent lives
      -SkipTamper                           skip the tamper test (it leaves one record stuck in 'quarantined')
#>
param(
    [string]$Base = "http://127.0.0.1:8000",
    [string]$TargetPath = (Join-Path $env:TEMP "test_agent.exe"),
    [string]$QuarantineDir = "C:\GeoTrench\quarantine",
    [switch]$SkipTamper
)

$ErrorActionPreference = "Stop"
$script:Pass = 0
$script:Fail = 0
$ResetScript = Join-Path $PSScriptRoot "reset_test_agent.ps1"

# ---------- helpers ----------

function Check([string]$Name, [bool]$Cond, [string]$Detail = "") {
    if ($Cond) {
        Write-Host "[PASS] $Name" -ForegroundColor Green
        $script:Pass++
    } else {
        Write-Host "[FAIL] $Name" -ForegroundColor Red
        if ($Detail) { Write-Host "       $Detail" -ForegroundColor DarkGray }
        $script:Fail++
    }
}

function Section([string]$Title) {
    Write-Host ""
    Write-Host "== $Title ==" -ForegroundColor Cyan
}

# Calls the API and never throws on 4xx/5xx. Returns Status, Raw (text), Body (parsed JSON or $null).
# Works on Windows PowerShell 5.1 and PowerShell 7.
function Invoke-Api([string]$Method, [string]$Path, [string]$BodyJson = $null) {
    $p = @{ Uri = "$Base$Path"; Method = $Method; UseBasicParsing = $true; ErrorAction = "Stop" }
    if ($BodyJson) { $p.Body = $BodyJson; $p.ContentType = "application/json" }
    $code = 0; $raw = ""
    try {
        $r = Invoke-WebRequest @p
        $code = [int]$r.StatusCode
        $raw = [string]$r.Content
    } catch {
        $resp = $_.Exception.Response
        if (-not $resp) { throw "Backend unreachable at $Base ($($_.Exception.Message))" }
        $code = [int]$resp.StatusCode
        $raw = $_.ErrorDetails.Message
        if (-not $raw) {
            try { $raw = (New-Object System.IO.StreamReader($resp.GetResponseStream())).ReadToEnd() } catch { $raw = "" }
        }
    }
    $obj = $null
    try { $obj = $raw | ConvertFrom-Json } catch { }
    [pscustomobject]@{ Status = $code; Raw = $raw; Body = $obj }
}

# Pulls the message out of {ok, message} or a FastAPI-style {detail: ...} body.
function Get-Msg($Resp) {
    $b = $Resp.Body
    if ($null -eq $b) { return $Resp.Raw }
    if ($b.PSObject.Properties["message"]) { return [string]$b.message }
    if ($b.PSObject.Properties["detail"]) {
        $d = $b.detail
        if ($d -is [string]) { return $d }
        if ($d.PSObject.Properties["message"]) { return [string]$d.message }
        return ($d | ConvertTo-Json -Compress -Depth 5)
    }
    return $Resp.Raw
}

# Finds the record array in the /api/quarantine/list response, whatever it's called.
function Get-Records {
    $r = Invoke-Api GET "/api/quarantine/list"
    $b = $r.Body
    if ($null -eq $b) { return @() }
    if ($b -is [array]) { return $b }
    foreach ($name in "records", "items", "quarantine", "entries", "data") {
        if ($b.PSObject.Properties[$name]) {
            $v = $b.$name
            if ($v -is [array]) { return $v }
            if ($v -and $v.PSObject.Properties["records"]) { return @($v.records) }
            if ($v) { return @($v) }
        }
    }
    return @()
}

function Get-Id($Rec) {
    if ($Rec.PSObject.Properties["manifest_id"]) { return $Rec.manifest_id }
    return $Rec.id
}

function Find-Record($Id) {
    Get-Records | Where-Object { "$(Get-Id $_)" -eq "$Id" } | Select-Object -First 1
}

# Returns a list of problems if the text leaks a real path, the username, or private fields.
function Find-Leaks([string]$Raw) {
    $problems = @()
    if (-not $Raw) { return $problems }
    $t = $Raw -replace '\\\\', '\'          # un-escape JSON backslashes
    $u = [regex]::Escape($env:USERNAME)
    if ($t -match "(?i)\\Users\\$u(\\|$|`")") { $problems += "contains real username path" }
    if ($t -match "(?i)GeoTrench\\quarantine") { $problems += "contains quarantine folder path" }
    if ($t -match "original_path_private")     { $problems += "contains original_path_private" }
    if ($t -match "`"quarantine_path`"")       { $problems += "contains quarantine_path" }
    return $problems
}

function Check-NoLeak([string]$Name, [string]$Raw) {
    $p = Find-Leaks $Raw
    Check $Name ($p.Count -eq 0) ($p -join "; ")
}

function Restore($Id) {
    Invoke-Api POST "/api/quarantine/restore" (@{ manifest_id = $Id } | ConvertTo-Json -Compress)
}

function Get-QuarFiles {
    if (-not (Test-Path $QuarantineDir)) { return @() }
    @(Get-ChildItem -Path $QuarantineDir -Filter *.quar -File -ErrorAction SilentlyContinue)
}

function Agent-Running {
    $null -ne (Get-Process -Name test_agent -ErrorAction SilentlyContinue)
}

# Runs reset_test_agent.ps1 -Quarantine and returns the id of the newly created quarantined record.
function New-QuarantinedAgent {
    $before = @(Get-Records | ForEach-Object { "$(Get-Id $_)" })
    Write-Host "  running reset_test_agent.ps1 -Quarantine ..." -ForegroundColor DarkGray
    & $ResetScript -Quarantine | Out-Host
    Start-Sleep -Milliseconds 500
    $new = Get-Records | Where-Object {
        ($before -notcontains "$(Get-Id $_)") -and ($_.status -eq "quarantined")
    } | Select-Object -Last 1
    if (-not $new) { return $null }
    return (Get-Id $new)
}

function Abort([string]$Why) {
    Write-Host ""
    Write-Host "ABORTED: $Why" -ForegroundColor Red
    Write-Host "Passed $script:Pass, failed $script:Fail before aborting."
    exit 1
}

# ---------- 0. preflight ----------

Section "0. Preflight"
if (-not (Test-Path $ResetScript)) { Abort "reset_test_agent.ps1 not found next to this script ($PSScriptRoot)." }
$h = Invoke-Api GET "/api/health"
Check "Backend reachable (/api/health = 200)" ($h.Status -eq 200) "status $($h.Status)"
if ($h.Status -ne 200) { Abort "Start the backend first: python -m uvicorn server:app --port 8000" }

# ---------- 1. happy path ----------

Section "1. Happy path"
$id1 = New-QuarantinedAgent
if ($null -eq $id1) { Abort "No new 'quarantined' record appeared. Fix the 7D quarantine test first." }
Write-Host "  quarantined record id: $id1" -ForegroundColor DarkGray

$quarBefore = (Get-QuarFiles).Count
$r = Restore $id1
Check "Restore returns 200" ($r.Status -eq 200) "status $($r.Status): $(Get-Msg $r)"
Check "Message is exact" ((Get-Msg $r) -eq "Restored to original location. Not relaunched.") "got: $(Get-Msg $r)"
Check-NoLeak "Restore response has no real paths or private fields" $r.Raw
if ($r.Body -and $r.Body.PSObject.Properties["restored_to"]) {
    Check "restored_to is redacted (<user>)" ($r.Body.restored_to -match "<user>") "got: $($r.Body.restored_to)"
}
Start-Sleep -Seconds 1
Check "File is back at original location" (Test-Path $TargetPath) $TargetPath
Check "One .quar file removed from quarantine folder" ((Get-QuarFiles).Count -eq ($quarBefore - 1)) "before $quarBefore, after $((Get-QuarFiles).Count)"
Check "Program was NOT relaunched" (-not (Agent-Running))

$listRaw = (Invoke-Api GET "/api/quarantine/list").Raw
$rec = Find-Record $id1
Check "List shows status 'restored'" ($rec -and $rec.status -eq "restored") "status: $($rec.status)"
Check "List shows restored_at" ($rec -and $rec.PSObject.Properties["restored_at"] -and $rec.restored_at)
Check-NoLeak "List response has no real paths or private fields" $listRaw

# ---------- 2. refusals ----------

Section "2. Refusals"
$r = Restore $id1
Check "Second restore of same id -> 409" ($r.Status -eq 409) "status $($r.Status)"
Check "Message: Not in quarantine (status: restored)." ((Get-Msg $r) -eq "Not in quarantine (status: restored).") "got: $(Get-Msg $r)"

$r = Restore 99999999
Check "Unknown id -> 404" ($r.Status -eq 404) "status $($r.Status)"
Check "Message: Quarantine record not found." ((Get-Msg $r) -eq "Quarantine record not found.") "got: $(Get-Msg $r)"

$r = Invoke-Api POST "/api/quarantine/restore" (@{ manifest_id = $id1; path = "C:\x" } | ConvertTo-Json -Compress)
Check "Extra field rejected -> 422" ($r.Status -eq 422) "status $($r.Status)"
Check-NoLeak "Error responses have no real paths" $r.Raw

# ---------- 3. no-overwrite ----------

Section "3. No-overwrite"
$id2 = New-QuarantinedAgent
if ($null -eq $id2) {
    Check "Re-quarantine for overwrite test" $false "no new quarantined record appeared"
} else {
    Write-Host "  quarantined record id: $id2" -ForegroundColor DarkGray
    "dummy" | Out-File -FilePath $TargetPath -Encoding ascii
    $r = Restore $id2
    Check "Restore over existing file -> 409" ($r.Status -eq 409) "status $($r.Status)"
    Check "Message: A file already exists at the original location." ((Get-Msg $r) -eq "A file already exists at the original location.") "got: $(Get-Msg $r)"
    $content = (Get-Content -Path $TargetPath -Raw -ErrorAction SilentlyContinue)
    Check "Dummy file was NOT overwritten" ($content -and $content.Trim() -eq "dummy")
    $rec = Find-Record $id2
    Check "Record still 'quarantined'" ($rec -and $rec.status -eq "quarantined") "status: $($rec.status)"

    Remove-Item -Path $TargetPath -Force
    $r = Restore $id2
    Check "Restore after removing dummy -> 200" ($r.Status -eq 200) "status $($r.Status): $(Get-Msg $r)"
    Check "File is back again" (Test-Path $TargetPath)
}

# ---------- 4. tamper ----------

if ($SkipTamper) {
    Section "4. Tamper (skipped)"
} else {
    Section "4. Tamper"
    # Snapshot the folder first so we tamper with exactly the file this quarantine creates.
    # (LastWriteTime can't be used: every copy of test_agent.exe keeps curl.exe's original timestamp.)
    $quarNamesBefore = @(Get-QuarFiles | ForEach-Object { $_.Name })
    $id3 = New-QuarantinedAgent
    if ($null -eq $id3) {
        Check "Re-quarantine for tamper test" $false "no new quarantined record appeared"
    } else {
        Write-Host "  quarantined record id: $id3" -ForegroundColor DarkGray
        $newQuar = @(Get-QuarFiles | Where-Object { $quarNamesBefore -notcontains $_.Name })
        Check "Exactly one new .quar file appeared" ($newQuar.Count -eq 1) "found $($newQuar.Count) new files"
        $quar = $newQuar | Select-Object -First 1
        if (-not $quar -or $newQuar.Count -ne 1) {
            Check "Found .quar file to tamper with" $false "could not identify the new file in $QuarantineDir"
        } else {
            Write-Host "  tampering with: $($quar.Name)" -ForegroundColor DarkGray
            if ($quar.IsReadOnly) { $quar.IsReadOnly = $false }
            Add-Content -Path $quar.FullName -Value "x"
            $r = Restore $id3
            Check "Restore tampered file -> 409" ($r.Status -eq 409) "status $($r.Status)"
            Check "Message: File changed while in quarantine." ((Get-Msg $r) -eq "File changed while in quarantine.") "got: $(Get-Msg $r)"
            Check "Tampered file left in quarantine" (Test-Path $quar.FullName)
            Check "Tampered file NOT restored to original location" (-not (Test-Path $TargetPath))
            $rec = Find-Record $id3
            Check "Record still 'quarantined'" ($rec -and $rec.status -eq "quarantined") "status: $($rec.status)"
        }
    }
}

# ---------- 5. audit ----------

Section "5. Audit feed"
$a = Invoke-Api GET "/api/audit?limit=20"
Check "Audit feed reachable" ($a.Status -eq 200) "status $($a.Status)"
Check "Audit contains 'Restored test_agent.exe'" ($a.Raw -match "Restored test_agent\.exe")
if (-not $SkipTamper) {
    Check "Audit mentions the tamper refusal" ($a.Raw -match "(?i)changed")
}
Check-NoLeak "Audit feed has no real paths" $a.Raw

# ---------- summary ----------

Write-Host ""
Write-Host "==============================" -ForegroundColor Cyan
$color = if ($script:Fail -eq 0) { "Green" } else { "Red" }
Write-Host "Passed: $script:Pass   Failed: $script:Fail" -ForegroundColor $color
Write-Host "==============================" -ForegroundColor Cyan
Write-Host "Manual check: scroll the SERVER window and confirm no log line shows a real path or your username."
if (-not $SkipTamper) {
    Write-Host "Note: the tampered record stays 'quarantined' on purpose. Delete its .quar by hand if you want a clean folder."
}
if ($script:Fail -gt 0) { exit 1 } else { exit 0 }