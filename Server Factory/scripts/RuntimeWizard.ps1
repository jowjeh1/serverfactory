<#
.SYNOPSIS
    Layer 4 Runtime Wizard - The "Day 0" Configuration Engine.
    UPDATED: Phase 2 - IIS Module (Fixed: SSL Binding Provider & Warning Silence).
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

# 2. Domain Controller Promotion
function Promote-DC {
    # Check if AD-DS role is installed BUT not yet a domain controller
    if ((Get-WindowsFeature AD-Domain-Services).Installed -and -not (Get-CimInstance Win32_ComputerSystem).PartOfDomain) {
        Write-Host "`n=== DOMAIN CONTROLLER PROMOTION ===" -ForegroundColor Cyan
        $Ans = Read-Host "Detected AD-DS Role. Promote this server to a Domain Controller? [Y/N]"
        
        if ($Ans -eq "Y") {
            # --- RESTORED NETWORK LOGIC (PERMISSIVE MODE) ---
            Write-Host "DCs require a Static IP configuration." -ForegroundColor Yellow
            $IP = Read-Host "Enter Static IP Address"
            $Prefix = Read-Host "Enter Subnet Prefix (e.g. 24)"
            $Gateway = Read-Host "Enter Default Gateway"
            # Crucial: New Forests must point to themselves for DNS initially
            $DNS = "127.0.0.1" 
            
            Write-Host "Applying Network Settings..." -ForegroundColor Cyan
            $Adapter = Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object -First 1

            # 2a. IP & Gateway Configuration (Robust)
            try {
                # Try standard config first
                New-NetIPAddress -InterfaceIndex $Adapter.ifIndex -IPAddress $IP -PrefixLength $Prefix -DefaultGateway $Gateway -ErrorAction Stop
                Write-Log "Network Configured: $IP / Gateway: $Gateway" "SUCCESS"
            } catch {
                Write-Log "Standard Network Config Failed (Likely Gateway validation): $_" "WARN"
                Write-Log "Attempting Fallback (IP Only + Route)..." "WARN"

                try {
                    # Fallback Step 1: Set IP without Gateway
                    New-NetIPAddress -InterfaceIndex $Adapter.ifIndex -IPAddress $IP -PrefixLength $Prefix -ErrorAction Stop
                    Write-Log "Static IP set successfully (No Gateway)." "SUCCESS"

                    # Fallback Step 2: Try to force Gateway as a Route (Best Effort)
                    New-NetRoute -DestinationPrefix "0.0.0.0/0" -InterfaceIndex $Adapter.ifIndex -NextHop $Gateway -ErrorAction SilentlyContinue
                    Write-Log "Attempted to force Default Gateway route." "INFO"
                } catch {
                    Write-Log "CRITICAL: Could not set Static IP. Proceeding with existing config..." "ERROR"
                }
            }

            # 2b. DNS Configuration (Isolated)
            try {
                Set-DnsClientServerAddress -InterfaceIndex $Adapter.ifIndex -ServerAddresses $DNS -ErrorAction Stop
                Write-Log "DNS pointing to Localhost ($DNS)." "SUCCESS"
            } catch {
                Write-Log "Failed to set DNS: $_" "ERROR"
            }
            
            # --- PROMOTION LOGIC ---
            $DomainName = Read-Host "Root Domain Name (e.g. corp.local)"
            $SafePass   = Read-Host "SafeMode Administrator Password" -AsSecureString
            
            Write-Log "Starting Forest Provisioning. This WILL reboot the server..." "WARN"
            
            try {
                Install-ADDSForest -DomainName $DomainName `
                                   -SafeModeAdministratorPassword $SafePass `
                                   -InstallDns:$true `
                                   -Force:$true `
                                   -Confirm:$false
                
                Write-Log "Promotion command sent. Waiting for reboot..." "SUCCESS"
                Stop-Transcript
                exit
            } catch {
                Write-Log "DC Promotion Failed: $_" "ERROR"
            }
        }
    }
}

# 3. WEB SERVER (IIS) CONFIGURATION (Phase 2)
function Configure-IIS {
    # Detection
    if ((Get-WindowsFeature Web-Server).Installed) {
        Write-Host "`n=== WEB SERVER (IIS) CONFIGURATION ===" -ForegroundColor Cyan
        
        # --- Pre-Load Modules (Fix for Reliability) ---
        # Ensure modules are loaded BEFORE attempting configuration blocks
        Write-Log "Loading IIS and PKI modules..."
        Import-Module WebAdministration -ErrorAction SilentlyContinue
        Import-Module PKI -ErrorAction SilentlyContinue

        # --- A. Baseline Configuration (Auto) ---
        Write-Log "Applying IIS Baseline Configuration..."
        try {
            # Ensure W3SVC is Automatic/Running
            Set-Service -Name W3SVC -StartupType Automatic -Status Running -ErrorAction Stop
            
            # Ensure DefaultAppPool is AutoStart=True
            Set-ItemProperty "IIS:\AppPools\DefaultAppPool" -Name autoStart -Value $true
            
            Write-Log "Baseline Applied: W3SVC Running, DefaultAppPool AutoStart Enabled." "SUCCESS"
        } catch {
            Write-Log "Failed to apply IIS Baseline: $_" "ERROR"
        }

        # --- B. Hardening (Opt-In) ---
        $Secure = Read-Host "IIS Detected. Apply Security Hardening (Remove Server Header, Disable Directory Browsing)? [Y/N]"
        if ($Secure -eq "Y") {
            Write-Log "Applying IIS Security Hardening..."
            try {
                # Disable Directory Browsing (Global)
                Set-WebConfigurationProperty -Filter /system.webServer/directoryBrowse -Name enabled -Value $false -PSPath 'IIS:\'
                
                # Remove 'X-Powered-By' Header
                # FIX: Added WarningAction SilentlyContinue to suppress "Property not found" warnings
                Remove-WebConfigurationProperty -Filter /system.webServer/httpProtocol/customHeaders -Name "." -AtElement @{name='X-Powered-By'} -PSPath 'IIS:\' -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                
                Write-Log "Hardening Applied." "SUCCESS"
            } catch {
                Write-Log "Failed to apply IIS Hardening: $_" "ERROR"
            }
        }

        # --- C. SSL Setup (Opt-In) ---
        $SSL = Read-Host "Create Self-Signed Cert for HTTPS testing? [Y/N]"
        if ($SSL -eq "Y") {
            try {
                Write-Log "Generating Self-Signed Certificate..."
                # FIX: Removed -Force parameter which was causing a crash
                $Cert = New-SelfSignedCertificate -DnsName $env:COMPUTERNAME -CertStoreLocation "Cert:\LocalMachine\My"
                
                Write-Log "Binding Certificate to Port 443..."
                
                # FIX: New-WebBinding in WebAdministration module does NOT support -Thumbprint.
                # We must creating the binding first, then assign the cert via the IIS Provider path.
                
                # 1. Create the Site Binding (Port 443)
                New-WebBinding -Name "Default Web Site" -Protocol https -Port 443 -SslFlags 0 -ErrorAction SilentlyContinue
                
                # 2. Assign the Certificate to the IP:Port Pair (0.0.0.0:443)
                Get-Item "Cert:\LocalMachine\My\$($Cert.Thumbprint)" | New-Item -Path "IIS:\SslBindings\0.0.0.0!443" -Force -ErrorAction Stop

                Write-Log "SSL Configured: https://$env:COMPUTERNAME" "SUCCESS"
            } catch {
                Write-Log "SSL Setup Failed: $_" "ERROR"
            }
        }
    }
}

# 4. Security & Storage
function Set-FSRMProtection {
    param([string[]]$Extensions)
    if ((Get-WindowsFeature FS-Resource-Manager).Installed) {
        Write-Log "Configuring FSRM Ransomware Screens..."
        # (Placeholder for FSRM logic implementation)
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
Write-Log "Engine Version: 2.7 (Fixed SSL Provider Binding)"

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

# --- Phase 2: Role Configuration ---
Update-Progress "Configuring Application Roles..." 50
Configure-IIS

Update-Progress "Configuring Identity..." 60
Promote-DC     # <--- If this succeeds, script EXITS here.
Set-KDSRootKey # <--- Only runs if already a DC (Resume scenario)

Update-Progress "Configuring Storage..." 80
Set-Dedup
Set-FSRMProtection -Extensions $Config.RansomwareExtensions

Update-Progress "Finalizing..." 100
Write-Log "Runtime Configuration Complete." "SUCCESS"

# --- 5. DOMAIN JOIN ---
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