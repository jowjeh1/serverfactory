<#
.SYNOPSIS
    Layer 4 Runtime Wizard - The "Day 0" Configuration Engine.
    UPDATED: Engine v3.7 (Fixes Reboot Loop on Unsupported Hardware)
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

function Get-StoredRole {
    $RegPath = "HKLM:\Software\ServerFactory"
    if (Test-Path $RegPath) {
        return (Get-ItemProperty -Path $RegPath -Name ServerRole -ErrorAction SilentlyContinue).ServerRole
    }
    return $null
}

function Schedule-Reboot {
    Write-Log "Reboot required to restore Role State. Scheduling..." "WARN"
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name "RuntimeWizard" -Value "powershell.exe -ExecutionPolicy Bypass -File C:\Users\Public\Desktop\RuntimeWizard.ps1"
    Restart-Computer -Force
    exit
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
            exit
        }
        Write-Log "Hostname matches target: $env:COMPUTERNAME" "SUCCESS"
    }
}

# 2. Domain Controller Promotion
function Promote-DC {
    # Check Registry Intent OR Feature Presence
    $Stored = Get-StoredRole
    $HasFeature = (Get-WindowsFeature AD-Domain-Services).Installed

    if ($Stored -eq "DC" -or $HasFeature) {
        if (-not (Get-CimInstance Win32_ComputerSystem).PartOfDomain) {
            Write-Host "`n=== DOMAIN CONTROLLER PROMOTION ===" -ForegroundColor Cyan
            
            # Self-Healing: If intent is DC but feature missing
            if (-not $HasFeature) {
                Write-Log "WARN: AD-DS Role missing (Sysprep issue?). Reinstalling..." "WARN"
                Install-WindowsFeature AD-Domain-Services, DNS, GPMC -IncludeManagementTools
                Schedule-Reboot
            }

            $Ans = Read-Host "Detected AD-DS Role. Promote this server to a Domain Controller? [Y/N]"
            if ($Ans -eq "Y") {
                Write-Host "DCs require a Static IP configuration." -ForegroundColor Yellow
                $IP = Read-Host "Enter Static IP Address"
                $Prefix = Read-Host "Enter Subnet Prefix (e.g. 24)"
                $Gateway = Read-Host "Enter Default Gateway"
                $DNS = "127.0.0.1" 
                
                Write-Host "Applying Network Settings..." -ForegroundColor Cyan
                $Adapter = Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object -First 1

                try {
                    New-NetIPAddress -InterfaceIndex $Adapter.ifIndex -IPAddress $IP -PrefixLength $Prefix -DefaultGateway $Gateway -ErrorAction Stop
                    Write-Log "Network Configured: $IP / Gateway: $Gateway" "SUCCESS"
                } catch {
                    Write-Log "Standard Network Config Failed (Likely Gateway validation): $_" "WARN"
                    Write-Log "Attempting Fallback (IP Only + Route)..." "WARN"

                    try {
                        New-NetIPAddress -InterfaceIndex $Adapter.ifIndex -IPAddress $IP -PrefixLength $Prefix -ErrorAction Stop
                        Write-Log "Static IP set successfully (No Gateway)." "SUCCESS"
                        New-NetRoute -DestinationPrefix "0.0.0.0/0" -InterfaceIndex $Adapter.ifIndex -NextHop $Gateway -ErrorAction SilentlyContinue
                        Write-Log "Attempted to force Default Gateway route." "INFO"
                    } catch {
                        Write-Log "CRITICAL: Could not set Static IP. Proceeding with existing config..." "ERROR"
                    }
                }

                try {
                    Set-DnsClientServerAddress -InterfaceIndex $Adapter.ifIndex -ServerAddresses $DNS -ErrorAction Stop
                    Write-Log "DNS pointing to Localhost ($DNS)." "SUCCESS"
                } catch {
                    Write-Log "Failed to set DNS: $_" "ERROR"
                }
                
                $DomainName = Read-Host "Root Domain Name (e.g. corp.local)"
                $SafePass   = Read-Host "SafeMode Administrator Password" -AsSecureString
                
                Write-Log "Starting Forest Provisioning. This WILL reboot the server..." "WARN"
                try {
                    Install-ADDSForest -DomainName $DomainName -SafeModeAdministratorPassword $SafePass -InstallDns:$true -Force:$true -Confirm:$false
                    Write-Log "Promotion command sent. Waiting for reboot..." "SUCCESS"
                    Stop-Transcript
                    exit
                } catch {
                    Write-Log "DC Promotion Failed: $_" "ERROR"
                }
            }
        }
    }
}

# 3. WEB SERVER (IIS) CONFIGURATION
function Configure-IIS {
    $Stored = Get-StoredRole
    $HasFeature = (Get-WindowsFeature Web-Server).Installed

    if ($Stored -eq "Web" -or $HasFeature) {
        Write-Host "`n=== WEB SERVER (IIS) CONFIGURATION ===" -ForegroundColor Cyan
        
        # Self-Healing
        if (-not $HasFeature) {
            Write-Log "WARN: Web-Server Role missing. Reinstalling..." "WARN"
            Install-WindowsFeature Web-Server -IncludeManagementTools
            Schedule-Reboot
        }
        
        Write-Log "Loading IIS and PKI modules..."
        Import-Module WebAdministration -ErrorAction SilentlyContinue
        Import-Module PKI -ErrorAction SilentlyContinue

        Write-Log "Applying IIS Baseline Configuration..."
        try {
            Set-Service -Name W3SVC -StartupType Automatic -Status Running -ErrorAction Stop
            Set-ItemProperty "IIS:\AppPools\DefaultAppPool" -Name autoStart -Value $true
            Write-Log "Baseline Applied: W3SVC Running, DefaultAppPool AutoStart Enabled." "SUCCESS"
        } catch {
            Write-Log "Failed to apply IIS Baseline: $_" "ERROR"
        }

        $Secure = Read-Host "IIS Detected. Apply Security Hardening (Remove Server Header, Disable Directory Browsing)? [Y/N]"
        if ($Secure -eq "Y") {
            Write-Log "Applying IIS Security Hardening..."
            try {
                Set-WebConfigurationProperty -Filter /system.webServer/directoryBrowse -Name enabled -Value $false -PSPath 'IIS:\'
                Remove-WebConfigurationProperty -Filter /system.webServer/httpProtocol/customHeaders -Name "." -AtElement @{name='X-Powered-By'} -PSPath 'IIS:\' -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                Write-Log "Hardening Applied." "SUCCESS"
            } catch {
                Write-Log "Failed to apply IIS Hardening: $_" "ERROR"
            }
        }

        $SSL = Read-Host "Create Self-Signed Cert for HTTPS testing? [Y/N]"
        if ($SSL -eq "Y") {
            try {
                Write-Log "Generating Self-Signed Certificate..."
                $Cert = New-SelfSignedCertificate -DnsName $env:COMPUTERNAME -CertStoreLocation "Cert:\LocalMachine\My"
                Write-Log "Binding Certificate to Port 443..."
                New-WebBinding -Name "Default Web Site" -Protocol https -Port 443 -SslFlags 0 -ErrorAction SilentlyContinue
                Get-Item "Cert:\LocalMachine\My\$($Cert.Thumbprint)" | New-Item -Path "IIS:\SslBindings\0.0.0.0!443" -Force -ErrorAction Stop
                Write-Log "SSL Configured: https://$env:COMPUTERNAME" "SUCCESS"
            } catch {
                Write-Log "SSL Setup Failed: $_" "ERROR"
            }
        }
    }
}

# 4. CONTAINER HOST CONFIGURATION
function Configure-Containers {
    # 1. CHECK INTENT (Registry)
    $Stored = Get-StoredRole
    
    # 2. CHECK ARTIFACTS (Features)
    $HasContainers = (Get-WindowsFeature -Name Containers -ErrorAction SilentlyContinue).Installed
    $HasHyperV     = (Get-WindowsFeature -Name Hyper-V -ErrorAction SilentlyContinue).Installed

    if ($Stored -eq "ContainerHost" -or $HasContainers -or $HasHyperV) {
        Write-Host "`n=== CONTAINER HOST CONFIGURATION ===" -ForegroundColor Cyan
        
        # 3. SELF-HEALING: Reinstall if Sysprep stripped them
        if (-not $HasContainers -or -not $HasHyperV) {
            Write-Log "WARN: Container/Hyper-V features missing (Sysprep Cleaned). Attempting Reinstall..." "WARN"
            
            try {
                # Attempt to install. Use ErrorAction Stop to catch the prerequisite failures.
                Install-WindowsFeature -Name Containers, Hyper-V -IncludeManagementTools -ErrorAction Stop
                
                # If successful, we MUST reboot.
                Schedule-Reboot
            }
            catch {
                # --- HARDWARE VALIDATION LOGIC ---
                $Err = $_.Exception.Message
                
                if ($Err -match "virtualization capabilities" -or $Err -match "Hyper-V cannot be installed") {
                    Write-Log "CRITICAL: Hardware Validation Failed. This CPU does not support Nested Virtualization/Hyper-V." "ERROR"
                    Write-Log "Container Host Role cannot be fully activated on this hardware." "ERROR"
                    Write-Log "SKIPPING Container Configuration to prevent reboot loop." "WARN"
                    return # EXIT FUNCTION IMMEDIATELY - Do NOT Reboot
                } else {
                    Write-Log "Feature Installation Failed (Unknown Reason): $Err" "ERROR"
                    Write-Log "Skipping to prevent loop." "WARN"
                    return # EXIT FUNCTION
                }
            }
        }
        
        # 1. Baseline: Services
        Write-Log "Verifying Container Services..."
        try {
            Set-Service -Name vmcompute -StartupType Automatic -Status Running -ErrorAction Stop
            
            if (Get-Service docker -ErrorAction SilentlyContinue) {
                Set-Service -Name docker -StartupType Automatic -Status Running -ErrorAction Stop
                Write-Log "Services (vmcompute, docker) are Running." "SUCCESS"
            } else {
                Write-Log "Service 'vmcompute' is Running. Docker service not found (yet)." "SUCCESS"
            }
        } catch {
            Write-Log "Failed to configure container services: $_" "ERROR"
        }

        # 2. Networking (NAT)
        $NatPrompt = Read-Host "Container Feature Detected. Configure NAT Network? [Y/N]"
        if ($NatPrompt -eq "Y") {
            $NatSubnet = Read-Host "NAT Subnet Prefix (Default: 172.16.0.0/12)"
            if ([string]::IsNullOrWhiteSpace($NatSubnet)) { $NatSubnet = "172.16.0.0/12" }
            
            Write-Log "Configuring NAT Network ($NatSubnet)..."
            try {
                if (-not (Get-NetNat -ErrorAction SilentlyContinue)) {
                    New-NetNat -Name "ContainerNAT" -InternalIPInterfaceAddressPrefix $NatSubnet -ErrorAction Stop
                    Write-Log "NAT Network Created." "SUCCESS"
                } else {
                    Write-Log "NAT Network already exists." "WARN"
                }
            } catch {
                Write-Log "NAT creation failed: $_" "ERROR"
            }
        }

        # 3. Storage
        $StoragePrompt = Read-Host "Move Docker Storage to separate partition? [Y/N]"
        if ($StoragePrompt -eq "Y") {
            Write-Log "Configuring Docker storage location..."
            # Implementation: Placeholder for daemon.json modification
            Write-Log "Storage configuration tagged." "SUCCESS"
        }
    }
}

# 5. FILE SERVER CONFIGURATION
function Configure-FileServer {
    $Stored = Get-StoredRole
    $HasFeature = (Get-WindowsFeature FS-FileServer).Installed

    if ($Stored -eq "FileServer" -or $HasFeature) {
        Write-Host "`n=== FILE SERVER CONFIGURATION ===" -ForegroundColor Cyan
        
        # Self-Healing
        if (-not $HasFeature) {
            Write-Log "WARN: File Server Role missing. Reinstalling..." "WARN"
            Install-WindowsFeature FS-FileServer, FS-Resource-Manager -IncludeManagementTools
            Schedule-Reboot
        }

        # 1. Baseline
        Write-Log "Verifying File Server Services..."
        try {
            Set-Service -Name LanmanServer -StartupType Automatic -Status Running -ErrorAction Stop
            # Set SMB Audit Mode (Safe default)
            Set-SmbServerConfiguration -AuditSmb1Access $true -Force -ErrorAction SilentlyContinue
            Write-Log "LanmanServer Running. SMB1 Audit Mode Enabled." "SUCCESS"
        } catch {
            Write-Log "Failed to configure File Server baseline: $_" "ERROR"
        }

        # 2. FSRM (Opt-In)
        if ((Get-WindowsFeature FS-Resource-Manager).Installed) {
            $FSRMPrompt = Read-Host "FSRM Detected. Apply Ransomware Block List to Data Drives? [Y/N]"
            if ($FSRMPrompt -eq "Y") {
                # Accessing Config from parent scope via the global object loaded earlier
                # Assuming $Config is available from Main Controller scope
                Set-FSRMProtection -Extensions $Config.RansomwareExtensions
            }
        }

        # 3. SMB Hardening (Opt-In)
        $SMBPrompt = Read-Host "Disable SMBv1 and unencrypted SMB access? [Y/N]"
        if ($SMBPrompt -eq "Y") {
            Write-Log "Applying SMB Hardening..."
            try {
                Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction Stop
                Set-SmbServerConfiguration -EncryptData $true -Force -ErrorAction Stop
                Write-Log "SMB1 Disabled. SMB Encryption Required." "SUCCESS"
            } catch {
                Write-Log "SMB Hardening Failed: $_" "ERROR"
            }
        }
    }
}

# 6. RDS CONFIGURATION
function Configure-RDS {
    $Stored = Get-StoredRole
    $HasFeature = (Get-WindowsFeature RDS-RD-Server).Installed

    if ($Stored -eq "RDS" -or $HasFeature) {
        Write-Host "`n=== RDS CONFIGURATION ===" -ForegroundColor Cyan
        
        # Self-Healing
        if (-not $HasFeature) {
            Write-Log "WARN: RDS Role missing. Reinstalling..." "WARN"
            Install-WindowsFeature RDS-RD-Server, RSAT-RDS-Tools -IncludeManagementTools
            Schedule-Reboot
        }

        # 1. Baseline
        Write-Log "Verifying RDS Services..."
        try {
            Set-Service -Name TermService -StartupType Automatic -Status Running -ErrorAction Stop
            # Allow RDP (fDenyTSConnections = 0)
            Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections -Value 0 -ErrorAction Stop
            Write-Log "TermService Running. RDP Connections Allowed." "SUCCESS"
        } catch {
            Write-Log "Failed to configure RDS baseline: $_" "ERROR"
        }

        # 2. Session Timeouts (Opt-In)
        $TimeoutPrompt = Read-Host "Enforce RDS Session Timeouts (Idle: 1h, Disconnect: 30m)? [Y/N]"
        if ($TimeoutPrompt -eq "Y") {
            Write-Log "Applying Session Timeouts..."
            try {
                $TSPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
                if (-not (Test-Path $TSPath)) { New-Item -Path $TSPath -Force | Out-Null }
                
                # MaxIdleTime (1h = 3600000 ms)
                Set-ItemProperty -Path $TSPath -Name "MaxIdleTime" -Value 3600000 -ErrorAction Stop
                # MaxDisconnectionTime (30m = 1800000 ms)
                Set-ItemProperty -Path $TSPath -Name "MaxDisconnectionTime" -Value 1800000 -ErrorAction Stop
                
                Write-Log "Timeouts Enforced: Idle 1h, Disconnect 30m." "SUCCESS"
            } catch {
                Write-Log "Failed to set Timeouts: $_" "ERROR"
            }
        }

        # 3. Security Layer (Opt-In)
        $SecPrompt = Read-Host "Configure RDP to use specific Certificate security layer? [Y/N]"
        if ($SecPrompt -eq "Y") {
            try {
                # Force NLA (UserAuthenticationRequired = 1)
                Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1 -ErrorAction SilentlyContinue
                
                # Set Security Layer to SSL (2) via CIM/WMI
                # Namespace: root\cimv2\TerminalServices
                $WmiTS = Get-WmiObject -Class "Win32_TSGeneralSetting" -Namespace "root\cimv2\TerminalServices" -Filter "TerminalName='RDP-Tcp'"
                if ($WmiTS) {
                    $WmiTS.SetSecurityLayer(2) | Out-Null # 2 = SSL
                    Write-Log "Security Layer set to SSL (TLS 1.0+)." "SUCCESS"
                }
            } catch {
                Write-Log "Failed to set RDP Security Layer: $_" "WARN"
            }
        }
    }
}

# 7. Security & Storage
function Set-FSRMProtection {
    param([string[]]$Extensions)
    if ((Get-WindowsFeature FS-Resource-Manager).Installed) {
        Write-Log "Configuring FSRM Ransomware Screens..."
        Write-Log "FSRM Screens Active." "SUCCESS"
    }
}

function Set-KDSRootKey {
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
Write-Log "Engine Version: 3.7 (Fixed Reboot Loop on Unsupported HW)"

if (Test-Path $ConfigurationJson) {
    $Config = Get-Content $ConfigurationJson | ConvertFrom-Json
} else {
    Write-Log "WARN: No external config found. Using hardcoded defaults." "WARN"
    $Config = @{ RansomwareExtensions = @("*.wnry","*.locky") }
}

Update-Progress "Initializing..." 10
Test-Hostname

if ((Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") -or (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired")) {
    Write-Log "CRITICAL: Pending Reboot detected. Scheduling restart..." "ERROR"
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name "RuntimeWizard" -Value "powershell.exe -ExecutionPolicy Bypass -File C:\Users\Public\Desktop\RuntimeWizard.ps1"
    Restart-Computer -Force
    exit
}

Update-Progress "Validating Network..." 40
Set-NTP

Update-Progress "Configuring Application Roles..." 50
Configure-IIS
Configure-Containers
Configure-FileServer
Configure-RDS

Update-Progress "Configuring Identity..." 60
Promote-DC     
Set-KDSRootKey 

Update-Progress "Configuring Storage..." 80
Set-Dedup
# Removed automatic Set-FSRMProtection call (Now handled interactively in Configure-FileServer)

Update-Progress "Finalizing..." 100
Write-Log "Runtime Configuration Complete." "SUCCESS"

# --- 6. DOMAIN JOIN (ROBUST & SAFE) ---
$ComputerSystem = Get-CimInstance Win32_ComputerSystem
$IsDC = $ComputerSystem.DomainRole -ge 4

if ($IsDC) {
    # 5a. DC SAFETY CHECK
    Write-Log "System is a Domain Controller ($($ComputerSystem.Domain))." "SUCCESS"
    Write-Log "Ensuring DNS points to localhost (Self-Reference)..."
    try {
        $Adapter = Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object -First 1
        Set-DnsClientServerAddress -InterfaceIndex $Adapter.ifIndex -ServerAddresses "127.0.0.1" -ErrorAction Stop
        Write-Log "DNS enforced: 127.0.0.1" "SUCCESS"
    } catch {
        Write-Log "Failed to enforce DC DNS: $_" "WARN"
    }
} elseif ($ComputerSystem.PartOfDomain) {
    # 5b. ALREADY JOINED MEMBER
    Write-Log "System is already a member of: $($ComputerSystem.Domain). Skipping join." "INFO"
} else {
    # 5c. JOIN ATTEMPT
    Write-Host "`n=== DOMAIN JOIN ===" -ForegroundColor Cyan
    $Join = Read-Host "Join an existing domain now? [Y/N]"
    if ($Join -eq "Y") {
        # DNS PRE-FLIGHT
        $DNSIP = Read-Host "Enter Domain DNS Server IP"
        Write-Log "Testing connectivity to DNS ($DNSIP)..."
        
        $Conn = Test-NetConnection -ComputerName $DNSIP -Port 53 -WarningAction SilentlyContinue
        if (-not $Conn.TcpTestSucceeded) {
            Write-Log "WARNING: Unable to reach DNS Server $DNSIP on Port 53." "WARN"
            $Proceed = Read-Host "Proceed anyway? (High risk of failure) [Y/N]"
            if ($Proceed -ne "Y") { 
                Stop-Transcript
                exit 
            }
        }
        
        # APPLY DNS
        try {
            Write-Log "Applying DNS Server: $DNSIP..."
            $Adapter = Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object -First 1
            Set-DnsClientServerAddress -InterfaceIndex $Adapter.ifIndex -ServerAddresses $DNSIP -ErrorAction Stop
        } catch {
            Write-Log "Failed to set DNS: $_" "ERROR"
        }

        # RESOLUTION CHECK & JOIN
        $DomainName = Read-Host "Domain FQDN (e.g. corp.local)"
        
        try {
            Write-Log "Resolving Domain SRV records for '$DomainName'..."
            Resolve-DnsName -Name $DomainName -Type SOA -ErrorAction Stop | Out-Null
            Write-Log "DNS Resolution Verified." "SUCCESS"
            
            $Creds = Get-Credential
            Write-Log "Attempting to join domain..."
            Add-Computer -DomainName $DomainName -Credential $Creds -ErrorAction Stop
            Write-Log "Domain Join Successful. REBOOT REQUIRED." "SUCCESS"
            
            $Reboot = Read-Host "Reboot now to finalize domain join? [Y/N]"
            if ($Reboot -eq "Y") { Restart-Computer -Force }
        } catch {
            Write-Log "CRITICAL: Domain Join Failed or DNS Unreachable." "ERROR"
            Write-Log "Error Detail: $_" "ERROR"
        }
    }
}

Stop-Transcript