# scripts/update.ps1
# Robust Windows Update Script (Optimized)
# Fixes: Handles "No Updates" gracefully, prevents race conditions, and logs cleanly.

Write-Host "--- Windows Update (Optimized) ---" -ForegroundColor Cyan

# 1. Service Health Check (Only repair if broken)
$WUA = Get-Service wuauserv -ErrorAction SilentlyContinue
if ($WUA.Status -ne 'Running') {
    Write-Host "WUA Service not running. Attempting start..." -ForegroundColor Yellow
    Start-Service wuauserv -ErrorAction SilentlyContinue
}

# 2. Install Tooling (Idempotent)
if (-not (Get-Module -ListAvailable PSWindowsUpdate)) {
    Write-Host "Installing PSWindowsUpdate module..."
    $null = Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction SilentlyContinue
    $null = Install-Module PSWindowsUpdate -Force -Confirm:$false -ErrorAction SilentlyContinue
}

# 3. Scan & Install
try {
    Write-Host "Scanning for updates..."
    
    # CRITICAL: Use -IgnoreReboot so Packer manages the lifecycle.
    # We use -AcceptAll to catch everything available.
    $Result = Get-WindowsUpdate -Install -AcceptAll -IgnoreReboot -Verbose -ErrorAction Stop
    
    # 4. Output Results
    if ($Result) {
        $Result | Select-Object KB, Title, Result | Format-Table -AutoSize | Out-String | Write-Host
        Write-Host "Updates triggered. Ready for Packer Restart." -ForegroundColor Green
    } else {
        Write-Host "No updates found. System is up to date." -ForegroundColor Green
    }

} catch {
    Write-Host "Error during update process: $_" -ForegroundColor Red
    
    # 5. Remediation (Only runs on failure)
    Write-Host "Attempting WUA Repair..." -ForegroundColor Yellow
    Stop-Service wuauserv -Force -ErrorAction SilentlyContinue
    Remove-Item "$env:SystemRoot\SoftwareDistribution" -Recurse -Force -ErrorAction SilentlyContinue
    Start-Service wuauserv
    Write-Host "Repair complete. Updates will be retried in the next pass."
}