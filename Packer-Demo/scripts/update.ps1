# scripts/update.ps1
# Robust Windows Update Script
# Fixes: Handles "No Updates" gracefully and prevents WinRM output hangs.

Write-Host "--- Starting Windows Update Process (Enhanced Stability) ---"

# 1. Install Tooling (Silence output to prevent hangs)
Write-Host "Installing PSWindowsUpdate module..."
$null = Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction SilentlyContinue
$null = Install-Module PSWindowsUpdate -Force -Confirm:$false -ErrorAction SilentlyContinue

# 2. Check for Updates
Write-Host "Scanning for available updates..."
try {
    # Retrieve list of updates (without installing yet)
    $Updates = Get-WindowsUpdate -ErrorAction Stop
}
catch {
    Write-Host "Error scanning for updates: $_"
    $Updates = $null
}

# 3. Handle Results
if (-not $Updates) {
    Write-Host "No updates found. System is up to date."
}
else {
    $Count = @($Updates).Count
    Write-Host "Found $Count update(s). Installing now..."
    
    # 4. Install Updates
    try {
        # CRITICAL: Use -IgnoreReboot so Packer manages the cycle.
        $Result = Get-WindowsUpdate -Install -AcceptAll -IgnoreReboot -ErrorAction Stop
        
        # Display clean summary
        $Result | Select-Object KB, Title, Result | Format-Table -AutoSize | Out-String | Write-Host

        # 5. HARDENED COMMIT & WAIT 
        Write-Host "Updates installed. Forcing WUA shutdown and waiting 60s for commitment..." -ForegroundColor Yellow
        
        # Stop Windows Update Service aggressively so it doesn't conflict with Packer's reboot
        Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
        
        # Explicit wait allows the system to write out pending registry/file operations
        Start-Sleep -Seconds 60 

    }
    catch {
        Write-Host "Update Installation Failed: $_" -ForegroundColor Red
        if ($_.Exception.Message -match "0xc1900401") {
             Write-Host "Error 0xc1900401: Prerequisite check failed (likely Pending Reboot)." -ForegroundColor Yellow
        }
    }
}

Write-Host "--- Windows Update Process Complete ---"