# build.ps1
# Enterprise Server Factory - Layer 3 Wrapper
# UPDATED: Now fully dynamic/portable. Run this from anywhere.

# 1. Set Context to Project Root
# This ensures that ".\packer.exe" and relative paths work regardless of where you open PowerShell.
$ScriptDir = $PSScriptRoot
$ProjectRoot = Resolve-Path "$ScriptDir\.."
Set-Location $ProjectRoot

Clear-Host
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "   ENTERPRISE SERVER FACTORY - LAYER 3"
Write-Host "   Root: $ProjectRoot"
Write-Host "=============================================" -ForegroundColor Cyan

# --- 2. ENVIRONMENT PREP ---
# Packer needs 'oscdimg' to build the Unattend ISO.
$AdkPath = "$ProjectRoot\tools\Oscdimg"
if (Test-Path "$AdkPath\oscdimg.exe") {
    if ($env:Path -notlike "*$AdkPath*") {
        $env:Path += ";$AdkPath"
        Write-Host " [System] Added 'tools' to PATH." -ForegroundColor Gray
    }
} else {
    Write-Host " [Warning] 'oscdimg.exe' not found at: $AdkPath" -ForegroundColor Yellow
    Write-Host "           Packer build may fail if it cannot create the unattended ISO." -ForegroundColor Yellow
}

# --- 3. INPUTS ---
Write-Host "`n[1] Configuration"
$VMName = Read-Host "    Hostname (Default: Server2022-L3)"
if ([string]::IsNullOrWhiteSpace($VMName)) { $VMName = "Server2022-L3" }

$CPU = Read-Host "    vCPU (Default: 2)"
if ([string]::IsNullOrWhiteSpace($CPU)) { $CPU = "2" }

$RAM = Read-Host "    RAM MB (Default: 4096)"
if ([string]::IsNullOrWhiteSpace($RAM)) { $RAM = "4096" }

Write-Host "`n[2] Select Role"
Write-Host "    [1] Web  [2] DC  [3] File  [4] RDS  [5] Container  [6] Mgmt  [7] Generic"
$RoleInput = Read-Host "    Select Option"
$Role = switch ($RoleInput) { 
    "1" {"Web"} "2" {"DC"} "3" {"FileServer"} "4" {"RDS"} "5" {"ContainerHost"} "6" {"Mgmt"} Default {"Generic"} 
}

# --- 4. BUILD ---
Write-Host "`n[3] Building Artifact ($Role)..." -ForegroundColor Cyan

# Check for Packer
if (-not (Test-Path ".\packer.exe")) {
    Write-Error "Packer.exe not found in Project Root ($ProjectRoot)!"
    exit
}

# Run Packer (Paths are now relative to Project Root)
$PackerCmd = ".\packer.exe build -force -var 'role=$Role' -var 'vm_name=$VMName' -var 'vm_cpu=$CPU' -var 'vm_ram=$RAM' 3-deploy.pkr.hcl"
Invoke-Expression $PackerCmd

# --- 5. AUTO-IMPORT ---
if ($LASTEXITCODE -eq 0) {
    $BuildDir = "$ProjectRoot\builds\deploy-$VMName"
    $VMCX = Get-ChildItem $BuildDir -Recurse -Filter "*.vmcx" | Select-Object -First 1
    
    if ($VMCX) {
        Write-Host "`n[4] Importing to Hyper-V..." -ForegroundColor Yellow
        $Existing = Get-VM -Name $VMName -ErrorAction SilentlyContinue
        if ($Existing) { 
            Stop-VM $VMName -Force -EA 0
            Remove-VM $VMName -Force -EA 0 
        }
        
        Import-VM -Path $VMCX.FullName -Register
        Start-VM -Name $VMName
        Write-Host "    SUCCESS: VM '$VMName' is running." -ForegroundColor Green
    }
}