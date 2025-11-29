# build.ps1
# Enterprise Server Factory - Layer 3 Wrapper
# FINAL VERSION: Handles ADK Path, Interactive Prompts, and Auto-Import/Start.

Clear-Host
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "   ENTERPRISE SERVER FACTORY - LAYER 3"
Write-Host "=============================================" -ForegroundColor Cyan

# --- 0. ENVIRONMENT PREP (CRITICAL FIX: ADK Path) ---
# Packer needs 'oscdimg' to build the Unattend ISO. We reference the local tools path.
$AdkPath = "$PSScriptRoot\..\tools\Oscdimg"
if (Test-Path "$AdkPath\oscdimg.exe") {
    if ($env:Path -notlike "*$AdkPath*") {
        $env:Path += ";$AdkPath"
        Write-Host " [System] Added 'tools' path to PATH for this session." -ForegroundColor Gray
    }
} else {
    Write-Host " [Warning] 'oscdimg.exe' not found in required path: $AdkPath" -ForegroundColor Yellow
    Write-Host "           Please copy oscdimg.exe into C:\Packer-Demo\tools\Oscdimg" -ForegroundColor Yellow
}

# --- 1. HARDWARE ---
Write-Host "`n[1] Hardware Specs"
$VMName = Read-Host "    Hostname (Default: Server2022-L3):"
if ([string]::IsNullOrWhiteSpace($VMName)) { $VMName = "Server2022-L3" }

$CPU = Read-Host "    vCPU [2, 4, 8] (Default: 2)"
if ([string]::IsNullOrWhiteSpace($CPU)) { $CPU = "2" }

$RAM = Read-Host "    RAM MB [2048, 4096, 8192, 16384] (Default: 4096)"
if ([string]::IsNullOrWhiteSpace($RAM)) { $RAM = "4096" }

# --- 2. ROLE SELECTION ---
Write-Host "`n[2] Server Role Selection"
Write-Host "    [1] Web Server (IIS)"
Write-Host "    [2] Domain Controller"
Write-Host "    [3] File Server"
Write-Host "    [4] RDS Session Host"
Write-Host "    [5] Container Host"
Write-Host "    [6] Management Tools"
Write-Host "    [7] Generic Base"

$RoleInput = Read-Host "    Select Role [1-7]"
$Role = "Generic" 

switch ($RoleInput) {
    "1" { $Role = "Web" }
    "2" { $Role = "DC" }
    "3" { $Role = "FileServer" }
    "4" { $Role = "RDS" }
    "5" { $Role = "ContainerHost" }
    "6" { $Role = "Mgmt" }
    "7" { $Role = "Generic" }
}

# --- 3. EXECUTE PACKER ---
Clear-Host
Write-Host "BUILDING: $VMName ($Role)" -ForegroundColor Green
$null = Read-Host "Press Enter to execute..."

# Run Packer
$PackerCommand = ".\packer.exe build -force -var 'role=$Role' -var 'vm_name=$VMName' -var 'vm_cpu=$CPU' -var 'vm_ram=$RAM' 3-deploy.pkr.hcl"
Invoke-Expression $PackerCommand

# --- 4. POST-BUILD REPORT & AUTO-IMPORT ---
if ($LASTEXITCODE -eq 0) {
    $BuildDir = "$PSScriptRoot\..\builds\deploy-$VMName"
    $VMCXPath = Get-ChildItem -Path $BuildDir -Recurse -Filter "*.vmcx" | Select-Object -First 1

    Write-Host "`n---------------------------------------------" -ForegroundColor Green
    Write-Host "   BUILD SUCCESSFUL"
    Write-Host "---------------------------------------------" -ForegroundColor Green
    
    if ($VMCXPath) {
        $VMCXPathFullName = $VMCXPath.FullName
        
        # --- AUTO-IMPORT LOGIC ---
        Write-Host "`nStarting Auto-Import into Hyper-V..." -ForegroundColor Yellow
        $ExistingVM = Get-VM -Name $VMName -ErrorAction SilentlyContinue
        
        if ($ExistingVM) {
            Write-Host "WARNING: VM '$VMName' already exists. Deleting old instance..." -ForegroundColor Yellow
            Stop-VM -Name $VMName -TurnOff -Force -ErrorAction SilentlyContinue
            Remove-VM -Name $VMName -Force -ErrorAction SilentlyContinue
        }

        try {
            Write-Host "Importing VM from $($VMCXPathFullName)..."
            Import-VM -Path $VMCXPathFullName -Register
            Write-Host "VM '$VMName' imported successfully." -ForegroundColor Green
            
            Start-VM -Name $VMName
            Write-Host "VM Started! Open Hyper-V Console to finalize (Layer 4 Wizard)." -ForegroundColor Cyan
        } catch {
            Write-Host "FATAL: Failed to Import/Start VM. You must import the folder manually." -ForegroundColor Red
            Write-Host "Error details: $_" -ForegroundColor Red
        }
    } else {
        Write-Host "Error: Could not find .vmcx file in $BuildDir" -ForegroundColor Red
    }
} else {
    Write-Host "`nPacker Build Failed. Skipping Import." -ForegroundColor Red
}

Pause