# scripts/update.ps1
# HYBRID EDITION v6: Resilience & Verification
# Changelog:
# - Added Network Retry for Tooling
# - Removed KB Sorting (Respects WUA Dependency Order)
# - Broadened Success Status Checks
# - Added Final Manual Verification Prompt
# - ADDED: Local Transcript Logging for debugging WinRM hangs
# - ADDED: Cleanup Logic via -Finalize switch
# - UPDATED: Removed Interactive Prompt for Automation Safety
# - FIXED: Result Array expansion (Cleaner Logs)
# - FIXED: Loop Break on Pending Reboot (Prevents infinite loop)
# - FIXED: Write-Error crash in Verification Gate (Use Write-Host + Exit 1)

param (
    [switch]$Finalize
)

# --- 0. LOCAL LOGGING SETUP ---
# Creates a persistent log inside the VM to debug if WinRM freezes
$LogDir = "C:\Logs"
$LogFile = "$LogDir\Update_Cycle.log"

if (-not (Test-Path $LogDir)) { New-Item -Path $LogDir -ItemType Directory -Force | Out-Null }
Start-Transcript -Path $LogFile -Append -IncludeInvocationHeader

Write-Host "--- Windows Update (Iterative v6) ---" -ForegroundColor Cyan
Write-Host "Internal Log Active: $LogFile" -ForegroundColor Gray

# 1. Service Health Check
$WUA = Get-Service wuauserv -ErrorAction SilentlyContinue
if ($WUA.Status -ne 'Running') {
    Write-Host "WUA Service not running. Attempting start..." -ForegroundColor Yellow
    Start-Service wuauserv -ErrorAction SilentlyContinue
}

# 2. Install Tooling (Resilient w/ Retry)
$ToolingAttempt = 0
$ToolingSuccess = $false
do {
    try {
        $ToolingAttempt++
        if (-not (Get-Module -ListAvailable PSWindowsUpdate)) {
            Write-Host "Installing PSWindowsUpdate module (Attempt $ToolingAttempt)..."
            $null = Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction Stop
            $null = Install-Module PSWindowsUpdate -Force -Confirm:$false -ErrorAction Stop
        }
        $ToolingSuccess = $true
    } catch {
        Write-Host "Tooling installation failed (Net/DNS issue?): $_" -ForegroundColor Yellow
        Start-Sleep -Seconds 5
    }
} until ($ToolingSuccess -or ($ToolingAttempt -ge 3))

# 3. Hybrid Update Logic
$MaxRetries = 3
$RetryCount = 0
$UpdatesFound = $true 

while ($UpdatesFound -and ($RetryCount -lt $MaxRetries)) {
    $RetryCount++
    Write-Host "`n>>> Update Cycle $RetryCount of $MaxRetries <<<" -ForegroundColor Cyan
    
    # 3a. Check for Pending Reboot INSIDE the loop
    # If a previous update in this session triggered a reboot requirement, we must stop and let Packer reboot.
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") {
        Write-Host " [INFO] Pending Reboot detected from previous cycle. Stopping internal loop." -ForegroundColor Yellow
        Write-Host "        Packer will handle the reboot between provisioners." -ForegroundColor Gray
        break # Exit the While loop
    }

    try {
        # STEP A: Scan First
        Write-Host "Scanning for available updates..."
        
        # FIX: Removed 'Sort-Object KB' to respect WUA dependency order (SSU before Cumulative)
        $Updates = Get-WindowsUpdate -AcceptAll -IgnoreReboot -ErrorAction Stop
        
        if (-not $Updates) {
            Write-Host "No new updates found." -ForegroundColor Green
            $UpdatesFound = $false
        } else {
            # Force array type
            $UpdateList = @($Updates)
            $Total = $UpdateList.Count
            Write-Host "Found $Total update(s). Installing iteratively..." -ForegroundColor Yellow
            
            # STEP B: Iterate and Install
            $Counter = 0
            foreach ($CurrentUpdate in $UpdateList) {
                $Counter++
                $KB = $CurrentUpdate.KB
                $ShortTitle = $CurrentUpdate.Title -replace ".*(KB\d+).*", "$1"
                if ($ShortTitle.Length -gt 50) { $ShortTitle = $ShortTitle.Substring(0,47) + "..." }
                
                Write-Host " [$Counter/$Total] Installing: $ShortTitle ($KB)..." -NoNewline
                
                try {
                    # Install JUST this specific update object
                    $Result = $CurrentUpdate | Install-WindowsUpdate -AcceptAll -IgnoreReboot -ErrorAction Stop
                    
                    # CLEANUP: Handle array returns to prevent "Installed Installed Installed" logs
                    $StatusText = $Result.Result
                    if ($StatusText -is [System.Array]) {
                        $StatusText = ($StatusText | Select-Object -Unique) -join ", "
                    }

                    # FIX: expanded status check to avoid false negatives
                    if ($StatusText -match "Accepted|Installed|Succeeded|Completed") {
                        Write-Host " [SUCCESS] ($StatusText)" -ForegroundColor Green
                    } else {
                        Write-Host " [DONE] ($StatusText)" -ForegroundColor Green
                    }
                } catch {
                    Write-Host " [FAILED]" -ForegroundColor Red
                    Write-Host "    Error: $_" -ForegroundColor Red
                    # Continue to next update (Fault Tolerance)
                }
            }
            
            Write-Host "`nCycle complete. Re-checking for nested updates..."
        }
    }
    catch {
        Write-Host "Critical error during cycle: $_" -ForegroundColor Red
        # Self-Healing
        Stop-Service wuauserv -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 5
        Start-Service wuauserv
    }
}

# 4. Final Reboot Check (Logging only)
if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") {
    Write-Host " [INFO] Windows reports a reboot is PENDING. Exiting to allow Packer reboot." -ForegroundColor Yellow
}

# 5. FINAL VERIFICATION GATE
Write-Host "`n--- Final Verification Check ---" -ForegroundColor Cyan
try {
    Write-Host "Performing one last scan to ensure cleanliness..."
    $FinalCheck = Get-WindowsUpdate -AcceptAll -IgnoreReboot -ErrorAction SilentlyContinue
    
    if ($FinalCheck) {
        # CRITICAL FIX: If we are in Finalize mode but find updates, FAIL.
        
        if ($Finalize) {
            Write-Host "CRITICAL FAILURE: The following updates are STILL pending:" -ForegroundColor Red
            $FinalCheck | Select-Object KB, Title, Size, Result | Format-Table -AutoSize
            
            Write-Host "Golden Image Verification Failed: System is not fully patched after 3 cycles." -ForegroundColor Red
            
            # Close Log Before Exiting
            Stop-Transcript
            exit 1 # Stops Packer
        } else {
            Write-Host "Updates still pending (Expected for Pass 1/2). Proceeding to reboot." -ForegroundColor Yellow
        }

    } else {
        Write-Host "Verification Passed: System is 100% up to date." -ForegroundColor Green

        # --- CLEANUP LOGIC (Triggered only by -Finalize switch) ---
        if ($Finalize) {
            Write-Host "Finalize Switch Active: Cleaning up build artifacts..." -ForegroundColor Cyan
            
            # 1. Stop Transcript to release the file handle
            Stop-Transcript
            
            # 2. Delete Logs
            Remove-Item -Path "C:\Logs" -Recurse -Force -ErrorAction SilentlyContinue
            
            # 3. Optional: Clear Windows Update Download Cache (Space Saver)
            Stop-Service wuauserv -Force -ErrorAction SilentlyContinue
            Remove-Item "C:\Windows\SoftwareDistribution\Download\*" -Recurse -Force -ErrorAction SilentlyContinue
            
            Write-Host "Cleanup Complete. Ready for Sysprep." -ForegroundColor Green
            exit 0
        }
    }
} catch {
    Write-Host "Verification Scan Failed: $_" -ForegroundColor Red
    Stop-Transcript
    exit 1
}

Write-Host "--- Update Process Complete ---" -ForegroundColor Cyan
Stop-Transcript
exit 0