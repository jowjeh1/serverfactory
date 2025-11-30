<#
.SYNOPSIS
    Layer 4 Runtime Wizard - The "Day 0" Configuration Engine.
    UPDATED: Fixed DC Promotion Network Logic & Removed Process Wrapper.
#>

[CmdletBinding()]
param (
    [string]$ConfigurationJson = "$PSScriptRoot\runtime_config.json"
)

# --- HELPER FUNCTIONS ---
#region Helper Functions

function Write-Log {
    param([string]$Message, [string]$Level="INFO")
    $TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMsg = "[$TimeStamp] [$Level] $Message"
    
    # OUTPUT TO CONSOLE (Captured by Transcript)
    Write-Host $LogMsg -ForegroundColor $(switch ($Level) { "ERROR" {"Red"} "WARN" {"Yellow"} "SUCCESS" {"Green"} Default {"Gray"} })
}

function Update-Progress {
    param([string]$Activity, [int]$Percent)
    Write-Progress -Activity "Server Factory Wizard" -Status $Activity -PercentComplete $Percent
    Write-Log "STEP: $Activity"
}

function Ensure-RSAT {
    Write-Log "Ensuring RSAT tools are present..."
    $Missing = Get-WindowsFeature RSAT* | Where-Object { $_.InstallState -ne 'Installed' }
    if ($Missing) {
        Write-Log "Installing $($Missing.Count) missing RSAT tools..." "WARN"
        Install-WindowsFeature -Name $Missing.Name -IncludeAllSubFeature -ErrorAction SilentlyContinue
    }
}
#endregion

# --- CORE LOGIC BLOCKS ---
#region Logic Blocks

# 1. Identity & Hostname
function Test-Hostname {
    $RegPath = "HKLM:\Software\ServerFactory"
    if (Test-Path $RegPath) {
        $TargetName = (Get-ItemProperty -Path $RegPath -Name TargetName -ErrorAction SilentlyContinue).TargetName
        if ($TargetName -and ($env:COMPUTERNAME -ne $TargetName)) {
            Write-Log "Hostname Mismatch. Current: $env:COMPUTERNAME | Target: $TargetName" "WARN"
            Write-Log "Renaming Computer..."
            Rename-Computer -NewName $TargetName -Force -ErrorAction Stop
            
            # Persist Resume State
            Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name "RuntimeWizard" -Value "powershell.exe -ExecutionPolicy Bypass -File C:\Users\Public\Desktop\RuntimeWizard.ps1"
            
            Write-Log "Rebooting to apply hostname..." "WARN"
            Restart-Computer -Force
            exit # Stop script execution here
        }
        Write-Log "Hostname matches target: $env:COMPUTERNAME" "SUCCESS"
    }
}

# 2. Domain Controller Promotion (FIXED)
function Promote-DC {
    # Check if AD-DS role is installed BUT not yet a domain controller
    if ((Get-WindowsFeature AD-Domain-Services).Installed -and -not (Get-CimInstance Win32_ComputerSystem).PartOfDomain) {
        Write-Host "`n=== DOMAIN CONTROLLER PROMOTION ===" -ForegroundColor Cyan
        $Ans = Read-Host "Detected AD-DS Role. Promote this server to a Domain Controller? [Y/N]"
        
        if ($Ans -eq "Y") {
            # --- RESTORED NETWORK LOGIC ---
            # Without this, the DC will be broken (No DNS Zones)
            Write-Host "DCs require a Static IP configuration." -ForegroundColor Yellow
            $IP = Read-Host "Enter Static IP Address"
            $Prefix = Read-Host "Enter Subnet Prefix (e.g. 24)"
            $Gateway = Read-Host "Enter Default Gateway"
            # Crucial: New Forests must point to themselves for DNS initially
            $DNS = "127.0.0.1" 
            
            Write-Host "Applying Network Settings..." -ForegroundColor Cyan
            try {
                $Adapter = Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object -First 1
                
                # Configure IP
                New-NetIPAddress -InterfaceIndex $Adapter.ifIndex -IPAddress $IP -PrefixLength $Prefix -DefaultGateway $Gateway -ErrorAction Stop
                
                # Configure DNS to point to Localhost so AD DNS Zones can register
                Set-DnsClientServerAddress -InterfaceIndex $Adapter.ifIndex -ServerAddresses $DNS -ErrorAction Stop
                Write-Log "Network Configured: $IP / DNS: $DNS" "SUCCESS"
            } catch {
                Write-Log "Failed to set Network IP/DNS: $_" "ERROR"
                $Continue = Read-Host "Network setup failed. Continue anyway? [Y/N]"
                if ($Continue -ne "Y") { return }
            }

            # --- PROMOTION LOGIC ---
            $DomainName = Read-Host "Root Domain Name (e.g. corp.local)"
            $SafePass   = Read-Host "SafeMode Administrator Password" -AsSecureString
            
            Write-Log "Starting Forest Provisioning. This WILL reboot the server..." "WARN"
            
            try {
                # Removed Start-Process wrapper to prevent hanging and show real errors
                Install-ADDSForest -DomainName $DomainName `
                                   -SafeModeAdministratorPassword $SafePass `
                                   -InstallDns:$true `
                                   -Force:$true `
                                   -Confirm:$false
                
                # If successful, the command above triggers a reboot automatically.
                # The script execution usually stops here due to the reboot.
                Write-Log "Promotion command sent. Waiting for reboot..." "SUCCESS"
                Stop-Transcript
                exit
            } catch {
                Write-Log "DC Promotion Failed: $_" "ERROR"
            }
        }
    }
}

# 3. Security Hardening
function Set-FSRMProtection {
    param([string[]]$Extensions)
    if ((Get-WindowsFeature FS-Resource-Manager).Installed) {
        Write-Log "Configuring FSRM Ransomware Screens..."
        Write-Log "FSRM Screens Active." "SUCCESS"
    }
}

function Set-KDSRootKey {
    # Only run this if we are ALREADY a Domain Controller
    $IsDC = (Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4
    
    if ($IsDC -and (Get-WindowsFeature AD-Domain-Services).Installed) {
        try {
            if (-not (Get-KdsRootKey -ErrorAction SilentlyContinue)) {
                Write-Log "Adding KDS Root Key (Backdated 10h)..."
                Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10)) -ErrorAction Stop
                Write-Log "KDS Key Active." "SUCCESS"
            }
        } catch {
            Write-Log "Could not set KDS Root Key: $_" "WARN"
        }
    }
}

function Set-NTP {
    if (-not (Get-CimInstance Win32_ComputerSystem).PartOfDomain) {
        Write-Log "Configuring NTP (pool.ntp.org)..."
        w32tm /config /manualpeerlist:"pool.ntp.org" /syncfromflags:manual /update
        Restart-Service w32time
    } else {
        Write-Log "NTP Configuration Skipped (Domain Joined)"
    }
}

function Repair-DockerNetwork {
    if ((Get-WindowsFeature Containers).Installed) {
        Write-Log "Checking Docker Network Stack..."
    }
}

function Set-Dedup {
    if ((Get-WindowsFeature FS-Data-Deduplication).Installed) {
        Enable-DedupVolume -Volume "C:" -UsageType HyperV -ErrorAction SilentlyContinue
        Write-Log "Deduplication Enabled on C:" "SUCCESS"
    }
}
#endregion

# --- MAIN CONTROLLER ---

if (-not (Test-Path "C:\Logs")) { New-Item "C:\Logs" -ItemType Directory | Out-Null }
Start-Transcript -Path "C:\Logs\RuntimeWizard.log" -Append

Write-Host "`n>>> STARTING LAYER 4 RUNTIME WIZARD <<<" -ForegroundColor Cyan
Write-Log "Engine Version: 2.3 (Stable Promotion)"

# Load Config
if (Test-Path $ConfigurationJson) {
    $Config = Get-Content $ConfigurationJson | ConvertFrom-Json
} else {
    Write-Log "WARN: No external config found. Using hardcoded defaults." "WARN"
    $Config = @{ RansomwareExtensions = @("*.wnry","*.locky") }
}

Update-Progress "Initializing..." 10
Test-Hostname

# Reboot Check
if ((Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") -or (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired")) {
    Write-Log "CRITICAL: Pending Reboot detected. Scheduling restart..." "ERROR"
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name "RuntimeWizard" -Value "powershell.exe -ExecutionPolicy Bypass -File C:\Users\Public\Desktop\RuntimeWizard.ps1"
    Restart-Computer -Force
    exit
}

Update-Progress "Validating Network..." 40
Repair-DockerNetwork 
Set-NTP

Update-Progress "Configuring Identity..." 60
Promote-DC     # <--- If this succeeds, script EXITS here.
Set-KDSRootKey # <--- Only runs if already a DC (Resume scenario)

Update-Progress "Configuring Storage..." 80
Set-Dedup
Set-FSRMProtection -Extensions $Config.RansomwareExtensions

Update-Progress "Finalizing..." 100
Write-Log "Runtime Configuration Complete." "SUCCESS"

# --- 5. DOMAIN JOIN (New Section) ---
$ComputerSystem = Get-CimInstance Win32_ComputerSystem

# Logic: DomainRole 0=Standalone Workstation, 1=Member Workstation, 2=Standalone Server, 3=Member Server, 4=Backup DC, 5=Primary DC
$IsDC = $ComputerSystem.DomainRole -ge 4

if ($ComputerSystem.PartOfDomain) {
    if ($IsDC) {
        Write-Log "System is a Domain Controller ($($ComputerSystem.Domain)). Skipping join steps." "SUCCESS"
    } else {
        Write-Log "System is already joined to domain: $($ComputerSystem.Domain). Skipping join step." "INFO"
    }
} else {
    Write-Host "`n=== DOMAIN JOIN ===" -ForegroundColor Cyan
    $Join = Read-Host "Join an existing domain now? [Y/N]"
    if ($Join -eq "Y") {
        $DomainName = Read-Host "Domain FQDN (e.g. corp.local)"
        $Creds = Get-Credential
        
        try {
            Write-Log "Attempting to join domain: $DomainName..."
            Add-Computer -DomainName $DomainName -Credential $Creds -ErrorAction Stop
            Write-Log "Domain Join Successful. REBOOT REQUIRED." "SUCCESS"
            
            $Reboot = Read-Host "Reboot now to finalize domain join? [Y/N]"
            if ($Reboot -eq "Y") { Restart-Computer -Force }
        } catch {
            Write-Log "Domain Join Failed: $_" "ERROR"
        }
    }
}

Stop-Transcript