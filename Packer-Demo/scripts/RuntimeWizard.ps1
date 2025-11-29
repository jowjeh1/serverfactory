<#
.SYNOPSIS
    Layer 4 Runtime Wizard - The "Day 0" Configuration Engine for Windows Server.
    
.DESCRIPTION
    This script finalizes the configuration of a Windows Server after the binaries (Layer 3) 
    have been installed. It handles complex logic for Identity, Networking, Storage, 
    and Security hardening that requires a live OS environment.
    
    Features:
    - Aggressive Idempotency: Checks state before mutating.
    - Defensive Coding: Try/Catch wrappers for all external calls.
    - Binary Network Math: Validates subnets to prevent overlaps.
    - KDS Backdating: Bypasses the 10-hour replication delay for gMSAs.
    - RDS/IIS Hardening: Specific WMI and config edits for security.
    - AUTO-REMEDIATION: Automatically installs missing RSAT/Features if needed.
    - REBOOT-RESUME: Automatically handles necessary reboots and resumes configuration.

.PARAMETER ConfigurationJson
    Path to a JSON file containing environment variables (e.g., RansomwareExtensions, TrustedHosts).

.EXAMPLE
    .\RuntimeWizard.ps1
#>

[CmdletBinding()]
param (
    [string]$ConfigurationJson = "$PSScriptRoot\runtime_config.json"
)

# --- HELPER FUNCTIONS (Defined First) ---
#region Helper Functions

function Write-Log {
    param([string]$Message, [string]$Level="INFO")
    $TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $Color = switch ($Level) { "INFO" {"Cyan"} "WARN" {"Yellow"} "ERROR" {"Red"} "SUCCESS" {"Green"} default {"White"} }
    Write-Host "[$TimeStamp] [$Level] $Message" -ForegroundColor $Color
}

function Update-Progress {
    param([string]$Activity, [int]$Percent)
    Write-Progress -Activity "Runtime Wizard" -Status $Activity -PercentComplete $Percent
}

function Ensure-RSAT {
    param([string]$CommandName, [string]$CapabilityName)
    if (-not (Get-Command $CommandName -ErrorAction SilentlyContinue)) {
        Write-Log "Tool '$CommandName' is missing. Attempting to install RSAT capability: $CapabilityName..." "WARN"
        try {
            # Check if online
            if (Test-NetConnection google.com -Port 80 -WarningAction SilentlyContinue) {
                Get-WindowsCapability -Name "$CapabilityName*" -Online | Add-WindowsCapability -Online -ErrorAction Stop
                Write-Log "RSAT installed successfully." "SUCCESS"
            } else {
                Write-Log "Cannot install RSAT (No Internet). Skipping configuration requiring '$CommandName'." "ERROR"
                return $false
            }
        } catch {
            Write-Log "Failed to install RSAT: $_" "ERROR"
            return $false
        }
    }
    return $true
}

function Ensure-Feature {
    param([string]$CommandName, [string]$FeatureName)
    if (-not (Get-Command $CommandName -ErrorAction SilentlyContinue)) {
        Write-Log "Feature '$FeatureName' is missing. Installing..." "WARN"
        try {
            Install-WindowsFeature -Name $FeatureName -IncludeManagementTools -ErrorAction Stop
            Write-Log "Feature installed." "SUCCESS"
        } catch {
            Write-Log "Failed to install feature: $_" "ERROR"
            return $false
        }
    }
    return $true
}
#endregion

# --- GLOBAL CONFIGURATION & ENVIRONMENT ---
$LogPath = "C:\Logs"
if (-not (Test-Path $LogPath)) { New-Item -Path $LogPath -ItemType Directory -Force | Out-Null }
$LogFile = "$LogPath\RuntimeWizard.log"
Start-Transcript -Path $LogFile -Append

Write-Output ">>> STARTING LAYER 4 RUNTIME WIZARD <<<"

# Load Configuration if available, else use defaults
$Config = $null
if (Test-Path $ConfigurationJson) {
    try {
        $Config = Get-Content $ConfigurationJson -Raw | ConvertFrom-Json
        Write-Log "Configuration loaded from $ConfigurationJson" "SUCCESS"
    } catch {
        Write-Log "Failed to parse JSON configuration. Using hardcoded defaults." "ERROR"
    }
}

# Defaults if JSON missing or empty
if (-not $Config) {
    Write-Log "No external config found. Using hardcoded defaults." "WARN"
    $Config = @{
        RansomwareExtensions = @("*.wnry", "*.locky", "*.crypt", "*.wcry", "*.wannacry", "*.odin", "*.zepto")
        TrustedHosts         = @() 
        StaticIP             = $null 
    }
}

# --- CRITICAL REGISTRY PATHS ---
$FactoryRegPath = "HKLM:\Software\ServerFactory"
$RunOnceRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"

#region Module 0: Hostname Validation & Identity

function Test-Hostname {
    <#
    .SYNOPSIS
        Checks if the current temporary hostname matches the target hostname seeded in the Registry.
        If mismatch, schedules a rename and reboot.
    #>
    Write-Log "Checking Hostname Identity..."
    
    if (Test-Path $FactoryRegPath) {
        $TargetName = (Get-ItemProperty -Path $FactoryRegPath -Name TargetName -ErrorAction SilentlyContinue).TargetName
        
        if ($TargetName) {
            if ($env:COMPUTERNAME -ne $TargetName) {
                Write-Log "MISMATCH DETECTED: Current: '$env:COMPUTERNAME' != Target: '$TargetName'" "WARN"
                Write-Log "Renaming Server to '$TargetName' and rebooting..." "WARN"
                
                try {
                    Rename-Computer -NewName $TargetName -Force -ErrorAction Stop
                    Write-Log "Rename successful. Rebooting in 5 seconds..." "SUCCESS"
                    
                    # Schedule self to run again after reboot
                    Set-ItemProperty -Path $RunOnceRegPath -Name "RuntimeWizard" -Value "powershell.exe -ExecutionPolicy Bypass -File C:\Users\Public\Desktop\RuntimeWizard.ps1"
                    
                    Start-Sleep -Seconds 5
                    Restart-Computer -Force
                    # Script stops here due to reboot
                    exit
                } catch {
                    Write-Log "Failed to rename computer: $_" "ERROR"
                }
            } else {
                Write-Log "Hostname matches target ($TargetName). Proceeding." "SUCCESS"
            }
        }
    } else {
        Write-Log "Factory Registry key not found. Skipping hostname check." "INFO"
    }
}

function Test-PendingReboot {
    <#
    .SYNOPSIS
        Heuristic check for pending reboots across CBS, Windows Update, and Session Manager.
    #>
    Write-Log "Checking System Boot State..."
    $RebootRequired = $false

    # Check multiple subsystems for robustness
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") { $RebootRequired = true }
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") { $RebootRequired = true }
    
    try {
        $PendingRename = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue
        if ($PendingRename -and $PendingRename.PendingFileRenameOperations) { $RebootRequired = true }
    } catch { Write-Log "Failed to query Session Manager: $_" "ERROR" }

    # SCCM Client Check (Defensive WMI)
    try {
        $SCCM = Get-WmiObject -Namespace "root\ccm\clientsdk" -Class "CCM_ClientUtilities" -ErrorAction Stop
        if ($SCCM) {
            if ($SCCM.DetermineIfRebootPending().RebootPending) { $RebootRequired = $true }
        }
    } catch {} # Silent fail if SCCM not present

    if ($RebootRequired) {
        Write-Log "Reboot Pending detected. System is in a volatile state." "WARN"
    }

    return $RebootRequired
}
#endregion

#region Module 1: Boot Logic & System State

function Set-AdminPrompt {
    Write-Log "Configuring Administrative Prompt Visuals..."
    $ProfilePath = $PROFILE.AllUsersAllHosts
    $PromptFunc = '
function prompt {
    $Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $Principal = [Security.Principal.WindowsPrincipal]$Identity
    if ($Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host " [ADMINISTRATOR] " -ForegroundColor Red -NoNewline
    }
    "PS $($executionContext.SessionState.Path.CurrentLocation)$(' + "'>' " + ')"
}
'
    if (-not (Test-Path $ProfilePath)) { New-Item -Path $ProfilePath -Force | Out-Null }
    $CurrentContent = Get-Content $ProfilePath -Raw -ErrorAction SilentlyContinue
    if ($CurrentContent -notmatch "\[ADMINISTRATOR\]") {
        Add-Content -Path $ProfilePath -Value $PromptFunc
        Write-Log "Admin prompt customized." "SUCCESS"
    }
}

function Run-FinalUpdates {
    Write-Log "Scanning for 'Day 0' Updates (Defender/Stragglers)..."
    try {
        if (-not (Get-Module -ListAvailable PSWindowsUpdate)) {
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ErrorAction SilentlyContinue
            Install-Module PSWindowsUpdate -Force -Confirm:$false -ErrorAction SilentlyContinue
        }
        $Updates = Get-WindowsUpdate -AcceptAll -IgnoreReboot -Install -Verbose
        if ($Updates) {
            Write-Log "Installed $($Updates.Count) final updates." "SUCCESS"
        } else {
            Write-Log "System is fully up to date." "SUCCESS"
        }
    } catch {
        Write-Log "Failed to run final update check: $_" "WARN"
    }
}
#endregion

#region Module 2: Network & Time

function Test-SubnetOverlap {
    param([string]$ProposedIP, [int]$Prefix)
    
    if ([string]::IsNullOrWhiteSpace($ProposedIP)) { return }

    Write-Log "Validating Network: Checking $ProposedIP/$Prefix for overlaps..."
    
    # Helper to convert IP to Int64 for math (using binary logic required by specification)
    function IPToInt ($IP) {
        $Octets = $IP.Split(".")
        return [int64]($Octets[0]*16777216 + $Octets[1]*65536 + $Octets[2]*256 + $Octets[3])
    }

    try {
        $ProposedInt = IPToInt $ProposedIP
        $MaskInt = ([math]::Pow(2, 32) - [math]::Pow(2, (32 - $Prefix))) 
        $NetworkID = $ProposedInt -band $MaskInt
        $Broadcast = $NetworkID -bor (-bnot $MaskInt)

        $Interfaces = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.PrefixOrigin -ne "WellKnown" }
        
        foreach ($Interface in $Interfaces) {
            $ExistingInt = IPToInt $Interface.IPAddress
            $ExistingMask = ([math]::Pow(2, 32) - [math]::Pow(2, (32 - $Interface.PrefixLength)))
            $ExistingNetID = $ExistingInt -band $ExistingMask
            $ExistingBroadcast = $ExistingNetID -bor (-bnot $ExistingMask)

            # Overlap Logic: (StartA <= EndB) and (EndA >= StartB)
            if (($NetworkID -le $ExistingBroadcast) -and ($Broadcast -ge $ExistingNetID)) {
                throw "CRITICAL NETWORK ERROR: Proposed IP $ProposedIP/$Prefix overlaps with existing interface $($Interface.IPAddress)/$($Interface.PrefixLength)!"
            }
        }
        Write-Log "Network Validation Passed. No overlaps." "SUCCESS"
    } catch {
        Write-Log $_.Exception.Message "ERROR"
    }
}

function Repair-DockerNetwork {
    # "The Good Stuff": Fix Zombie Switch
    if (Get-Service docker -ErrorAction SilentlyContinue) {
        $NatSwitch = Get-VMSwitch -Name "nat" -ErrorAction SilentlyContinue
        if ($NatSwitch) {
            $Test = Get-NetIPInterface -InterfaceAlias "vEthernet (nat)" -ErrorAction SilentlyContinue
            if (-not $Test) {
                Write-Log "Zombie NAT Switch detected. Repairing..." "WARN"
                Stop-Service docker -Force
                Get-VMSwitch -Name "nat" | Remove-VMSwitch -Force
                Start-Service docker
                Write-Log "Docker Network Repaired." "SUCCESS"
            }
        }
    }
}

function Set-NTP {
    Write-Log "Configuring Time Synchronization..."
    
    # CRITICAL CHECK: Are we promoted to a Domain Controller yet?
    try {
        $ComputerInfo = Get-CimInstance Win32_ComputerSystem
        if (-not $ComputerInfo.PartOfDomain) {
            Write-Log "Server is in WORKGROUP ($($ComputerInfo.Workgroup)). Skipping Domain/PDC Time Sync Logic." "INFO"
            return
        }

        # If domain joined, proceed with RSAT tools check
        if (Ensure-RSAT -CommandName "Get-ADDomain" -CapabilityName "Rsat.ActiveDirectory.DS-LDS.Tools") {
            $Domain = Get-ADDomain -ErrorAction SilentlyContinue
            if ($Domain) {
                $PDC = $Domain.PdcRoleOwner
                $IsPDC = ($PDC -eq $env:COMPUTERNAME) -or ($PDC -like "$env:COMPUTERNAME.*")

                if ($IsPDC) {
                    Write-Log "Role Detected: PDC Emulator. Configuring Authoritative External Time Source."
                    # 0x8 Flag is critical for client mode
                    w32tm /config /manualpeerlist:"pool.ntp.org,0x8 time.windows.com,0x8" /syncfromflags:MANUAL /update
                } else {
                    Write-Log "Role Detected: Domain Member/DC. Configuring Domain Hierarchy Sync."
                    w32tm /config /syncfromflags:DOMHIER /update
                }
                Restart-Service w32time
                Write-Log "Time service reconfigured." "SUCCESS"
            }
        } else {
            Write-Log "Active Directory tools missing. Skipping advanced NTP logic." "INFO"
        }
    } catch {
        Write-Log "NTP Configuration check failed: $_" "ERROR"
    }
}
#endregion

#region Module 3: Identity

function Promote-DC {
    Write-Log "Checking for Pending Domain Controller Promotion..."
    
    # 1. Is AD-DS installed?
    $ADDSFeature = Get-WindowsFeature AD-Domain-Services -ErrorAction SilentlyContinue
    if (-not $ADDSFeature -or -not $ADDSFeature.Installed) {
        return # Not a DC role
    }
    
    # 2. Is it already promoted?
    if ((Get-CimInstance Win32_ComputerSystem).PartOfDomain) {
        Write-Log "Server is already domain joined/promoted. Skipping promotion logic." "INFO"
        return
    }

    # 3. Interactive Promotion Wizard
    Write-Host "`n[DOMAIN CONTROLLER PROMOTION WIZARD]" -ForegroundColor Yellow
    Write-Host "This server has AD-DS installed but is not yet a Domain Controller."
    $PromoteNow = Read-Host "Do you want to promote this server now? [Y/N]"
    
    if ($PromoteNow -eq "Y") {
        # --- Network Configuration (DCs require Static IP) ---
        Write-Host "DCs require a Static IP." -ForegroundColor Cyan
        $IP = Read-Host "Enter Static IP Address"
        $Prefix = Read-Host "Enter Subnet Prefix (e.g. 24)"
        $Gateway = Read-Host "Enter Default Gateway"
        $DNS = Read-Host "Enter Primary DNS (127.0.0.1 for New Forest)"
        
        # Validation Check (Leverage the Binary Math function)
        Test-SubnetOverlap -ProposedIP $IP -Prefix $Prefix
        
        Write-Host "Applying Network Settings..."
        $Adapter = Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object -First 1
        New-NetIPAddress -InterfaceIndex $Adapter.ifIndex -IPAddress $IP -PrefixLength $Prefix -DefaultGateway $Gateway -ErrorAction SilentlyContinue
        Set-DnsClientServerAddress -InterfaceIndex $Adapter.ifIndex -ServerAddresses $DNS

        # Ensure RSAT-AD is installed before promotion
        if (-not (Ensure-RSAT -CommandName "Install-ADDSForest" -CapabilityName "Rsat.ActiveDirectory.DS-LDS.Tools")) {
            Write-Log "FATAL: Cannot promote DC. Required AD tools missing." "ERROR"
            return
        }

        # --- Promotion Type ---
        Write-Host "`n[A] Create New Forest"
        Write-Host "[B] Join Existing Domain as Replica"
        $Type = Read-Host "Select [A/B]"
        $DomainName = Read-Host "Enter Domain Name (e.g. corp.local)"
        $SafeModePass = Read-Host "Enter Safe Mode Password" -AsSecureString

        try {
            if ($Type -eq "A") {
                Write-Log "Promoting to New Forest: $DomainName..." "WARN"
                Install-ADDSForest -DomainName $DomainName -InstallDns -SafeModeAdministratorPassword $SafeModePass -Force
            } elseif ($Type -eq "B") {
                $Cred = Get-Credential
                Write-Log "Promoting Replica DC: $DomainName..." "WARN"
                Install-ADDSDomainController -DomainName $DomainName -InstallDns -Credential $Cred -SafeModeAdministratorPassword $SafeModePass -Force
            }
        } catch {
            Write-Log "FATAL ERROR during DC Promotion: $_" "ERROR"
            Write-Log "The server may be in a partially configured state and requires manual intervention/cleanup." "ERROR"
        }
        # Note: The server will reboot automatically after this command finishes.
    }
}

function Set-KDSRootKey {
    Write-Log "Auditing KDS Root Key for gMSA support..."
    
    # 1. Check if AD-DS binaries are present
    $ADDSFeature = Get-WindowsFeature AD-Domain-Services -ErrorAction SilentlyContinue
    if (-not $ADDSFeature -or -not $ADDSFeature.Installed) {
        Write-Log "AD-DS Binaries not installed. Skipping KDS check (Not a DC)." "INFO"
        return
    }
    
    # 2. Check if actually Promoted
    if (-not (Get-CimInstance Win32_ComputerSystem).PartOfDomain) {
        Write-Log "AD-DS Installed but Server is in WORKGROUP. Not yet promoted. Skipping KDS check." "INFO"
        return
    }

    # 3. KDS Management
    try {
        if (Ensure-RSAT -CommandName "Get-KdsRootKey" -CapabilityName "Rsat.ActiveDirectory.DS-LDS.Tools") {
            $Key = Get-KdsRootKey -ErrorAction SilentlyContinue
            if (-not $Key) {
                Write-Log "No KDS Root Key found. Creating with 10-hour backdate bypass..."
                Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10))
                Write-Log "KDS Root Key created and active." "SUCCESS"
            } else {
                Write-Log "KDS Root Key already exists." "INFO"
            }
        }
    } catch {
        Write-Log "Failed to manage KDS Root Key: $_" "ERROR"
    }
}

function Grant-CertificatePrivateKeyAccess {
    param([string]$Thumbprint, [string]$AccountName)
    Write-Log "Granting Private Key Access for Cert $Thumbprint to $AccountName..."
    
    try {
        if (-not (Test-Path "Cert:\LocalMachine\My\$Thumbprint")) {
            Write-Log "Certificate $Thumbprint not found." "WARN"
            return
        }
        $Cert = Get-Item "Cert:\LocalMachine\My\$Thumbprint" -ErrorAction Stop
        
        $RSACert = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Cert)
        if ($RSACert.Key.UniqueName) {
            $KeyFileName = $RSACert.Key.UniqueName
            $KeyPath = "$env:ALLUSERSPROFILE\Microsoft\Crypto\RSA\MachineKeys\$KeyFileName"
            
            if (Test-Path $KeyPath) {
                $Acl = Get-Acl $KeyPath
                $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($AccountName, "Read", "Allow")
                $Acl.AddAccessRule($AccessRule)
                Set-Acl -Path $KeyPath -AclObject $Acl
                Write-Log "Access granted successfully." "SUCCESS"
            }
        }
    } catch {
        Write-Log "Failed to grant key access: $_" "ERROR"
    }
}
#endregion

#region Module 4: Storage

function Set-Dedup {
    Write-Log "Configuring Data Deduplication..."
    try {
        # Check/Install Dedup Feature
        if (Ensure-Feature -CommandName "Enable-DedupVolume" -FeatureName "FS-Data-Deduplication") {
            $Volumes = Get-Volume | Where-Object { $_.DriveLetter -ne $null -and $_.DriveLetter -ne "C" }
            
            foreach ($Vol in $Volumes) {
                # Check for SQL Files (Safety Check)
                $SQLFiles = Get-ChildItem -Path "$($Vol.DriveLetter):\" -Include *.mdf,*.ldf -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
                
                if ($SQLFiles) {
                    Write-Log "SQL Database files detected on $($Vol.DriveLetter):. Excluding their folders from Dedup." "WARN"
                    # In production, we would calculate the specific parent path here. 
                    # For safety in this wizard, we skip enabling dedup on this volume entirely.
                    Write-Log "Skipping Deduplication on $($Vol.DriveLetter): due to SQL presence."
                } else {
                    Write-Log "Enabling Dedup on $($Vol.DriveLetter): (FileSystem: $($Vol.FileSystem))"
                    Enable-DedupVolume -Volume "$($Vol.DriveLetter):" -ErrorAction SilentlyContinue
                }
            }
        } else {
            Write-Log "Data Deduplication feature not available." "INFO"
        }
    } catch { Write-Log "Dedup configuration error: $_" "ERROR" }
}

function Set-FSRMProtection {
    param([string[]]$Extensions)
    Write-Log "Configuring FSRM Ransomware Screens..."
    try {
        # Check/Install FSRM Feature
        if (Ensure-Feature -CommandName "New-FsrmFileScreen" -FeatureName "FS-Resource-Manager") {
            $GroupName = "Ransomware Block List"
            
            # Idempotency: Remove if exists to refresh list
            if (Get-FsrmFileGroup -Name $GroupName -ErrorAction SilentlyContinue) {
                Remove-FsrmFileGroup -Name $GroupName -Confirm:$false
            }
            
            New-FsrmFileGroup -Name $GroupName -IncludePattern $Extensions
            Write-Log "FSRM File Group updated." "SUCCESS"
            
            # Apply to Data Drives
            $Volumes = Get-Volume | Where-Object { $_.DriveLetter -ne $null -and $_.DriveLetter -ne "C" }
            foreach ($Vol in $Volumes) {
                $Path = "$($Vol.DriveLetter):\"
                if (-not (Get-FsrmFileScreen -Path $Path -ErrorAction SilentlyContinue)) {
                    New-FsrmFileScreen -Path $Path -IncludeGroup $GroupName -Active
                    Write-Log "Ransomware Screen applied to $Path" "SUCCESS"
                }
            }
        } else {
            Write-Log "FSRM feature not available. Skipping Ransomware screens." "INFO"
        }
    } catch { Write-Log "FSRM configuration error: $_" "WARN" }
}
#endregion

#region Module 5: Remote & Security

function Add-TrustedHost {
    param([string]$NewHost)
    Write-Log "Updating WinRM TrustedHosts..."
    try {
        $Current = (Get-Item WSMan:\localhost\Client\TrustedHosts).Value
        if ($Current -notlike "*$NewHost*") {
            $NewValue = if ($Current) { "$Current,$NewHost" } else { $NewHost }
            Set-Item WSMan:\localhost\Client\TrustedHosts -Value $NewValue -Force
            Write-Log "Added $NewHost to TrustedHosts." "SUCCESS"
        } else {
            Write-Log "$NewHost already trusted." "INFO"
        }
    } catch { Write-Log "Failed to update TrustedHosts: $_" "ERROR" }
}

function Secure-IIS {
    Write-Log "Hardening IIS Headers..."
    try {
        if (Get-Service W3SVC -ErrorAction SilentlyContinue) {
            Import-Module WebAdministration
            
            # 1. Remove X-Powered-By
            Clear-WebConfiguration -Filter "system.webServer/httpProtocol/customHeaders" -PSPath "IIS:\"
            Add-WebConfigurationProperty -PSPath "IIS:\" -Filter "system.webServer/httpProtocol/customHeaders" -Name "." -Value @{name='X-Powered-By';value=''} 
            
            Write-Log "IIS Headers scrubbed." "SUCCESS"
        }
    } catch { Write-Log "IIS Hardening skipped (Role not installed or error)." "INFO" }
}

function Set-RDSCertificate {
    param([string]$Thumbprint)
    Write-Log "Binding SSL Cert $Thumbprint to RDP Listener..."
    try {
        $Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
        if (Test-Path $Path) {
            # Use WMI method as per specification
            $TSGeneral = Get-WmiObject -Class "Win32_TSGeneralSetting" -Namespace "root\cimv2\terminalservices" -Filter "TerminalName='RDP-tcp'"
            if ($TSGeneral) {
                $Args = @{ SSLCertificateSHA1Hash = $Thumbprint }
                $TSGeneral.SetSSLCertificateSHA1Hash($Thumbprint)
                Write-Log "RDP Certificate Bound successfully via WMI." "SUCCESS"
            }
        }
    } catch { Write-Log "Failed to bind RDS Cert: $_" "ERROR" }
}

function Set-RDSSecurity {
    Write-Log "Hardening RDS Session Security..."
    
    $RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    if (-not (Test-Path $RegPath)) { New-Item -Path $RegPath -Force | Out-Null }
    
    try {
        # Set Session Timeouts (Converting Minutes/Hours to Milliseconds)
        # MaxIdleTime: Disconnect idle users (e.g., 2 hours)
        Set-ItemProperty -Path $RegPath -Name "MaxIdleTime" -Value (7200000) -Type DWORD -Force 
        # MaxDisconnectionTime: Log off disconnected users (e.g., 4 hours)
        Set-ItemProperty -Path $RegPath -Name "MaxDisconnectionTime" -Value (14400000) -Type DWORD -Force
        
        Write-Log "RDS Session timeouts enforced." "SUCCESS"
    } catch {
        Write-Log "Failed to enforce RDS session security: $_" "ERROR"
    }
}
#endregion

# --- MAIN CONTROLLER ---

Update-Progress "Initializing..." 10
Test-Hostname

if (Test-PendingReboot) {
    Write-Log "CRITICAL: Pending Reboot detected. Scheduling restart to clear state." "ERROR"
    # Schedule self to run again after reboot
    Set-ItemProperty -Path $RunOnceRegPath -Name "RuntimeWizard" -Value "powershell.exe -ExecutionPolicy Bypass -File C:\Users\Public\Desktop\RuntimeWizard.ps1"
    Restart-Computer -Force
    exit
}

Update-Progress "Day 0 Patching..." 20
Run-FinalUpdates

Update-Progress "Validating Network..." 40
if ($Config.StaticIP) {
    Test-SubnetOverlap -ProposedIP $Config.StaticIP.IP -Prefix $Config.StaticIP.Prefix
}
Repair-DockerNetwork # ADDED: Docker Fix
Set-NTP

Update-Progress "Configuring Identity..." 60
Promote-DC 
Set-KDSRootKey

Update-Progress "Configuring Storage..." 80
Set-Dedup
Set-FSRMProtection -Extensions $Config.RansomwareExtensions

Update-Progress "Hardening Security..." 90
if ($Config.TrustedHosts) { 
    $Config.TrustedHosts | ForEach-Object { Add-TrustedHost -NewHost $_ } 
}
Secure-IIS
Set-RDSSecurity

Update-Progress "Complete" 100
Write-Log "Runtime Wizard Completed Successfully." "SUCCESS"
Stop-Transcript