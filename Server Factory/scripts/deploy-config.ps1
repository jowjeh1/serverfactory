# scripts/deploy-config.ps1
# Layer 3: Enterprise Role Configuration (Binaries Only)

$Role = $env:SERVER_ROLE
$VMName = $env:VM_NAME

Write-Host "--- APPLYING ROLE: $Role ---"

# --- NAME & ROLE SEEDING (CRITICAL: Must survive Sysprep) ---
# We use the Registry for persistence, as the file system (C:\ProgramData) is wiped by Sysprep.
$FactoryRegPath = "HKLM:\Software\ServerFactory"
if (-not (Test-Path $FactoryRegPath)) { New-Item -Path $FactoryRegPath -ItemType Directory -Force | Out-Null }

# SEED HOSTNAME
Set-ItemProperty -Path $FactoryRegPath -Name TargetName -Value $VMName

# SEED ROLE (NEW FIX: Ensures Layer 4 knows the role even if Sysprep strips features)
Set-ItemProperty -Path $FactoryRegPath -Name ServerRole -Value $Role

Write-Host "Identity '$VMName' and Role '$Role' seeded to Registry."

# --- INSTALL BINARIES (Layer 3's core function) ---
switch ($Role) {
    "Web" {
        Write-Host "Installing IIS..."
        Install-WindowsFeature -Name Web-Server -IncludeManagementTools
    }
    "FileServer" {
        Write-Host "Installing File Services..."
        Install-WindowsFeature -Name FS-FileServer, FS-Resource-Manager -IncludeManagementTools
    }
    "RDS" {
        Write-Host "Installing Remote Desktop Session Host..."
        Install-WindowsFeature -Name RDS-RD-Server, RSAT-RDS-Tools -IncludeManagementTools
    }
    "ContainerHost" {
        Write-Host "Installing Containers & Hyper-V..."
        Install-WindowsFeature -Name Containers, Hyper-V -IncludeManagementTools
    }
    "Mgmt" {
        Write-Host "Installing Admin Tools (RSAT)..."
        Install-WindowsFeature -Name RSAT -IncludeAllSubFeature
    }
    "DC" {
        Write-Host "Installing AD DS Binaries..."
        Install-WindowsFeature -Name AD-Domain-Services, DNS, GPMC -IncludeManagementTools
    }
    Default { Write-Host "Generic Server." }
}

# --- CLEANUP (Standard practice before WinRM disconnects) ---
Write-Host "Cleaning up..."
Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue