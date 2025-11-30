# scripts/build.ps1
# Enterprise Server Factory - Master Build Wrapper
# Manages the full lifecycle: Layer 1 (Base), Layer 2 (Patch), Layer 3 (Deploy)

# 1. Set Context to Project Root
$ScriptDir = $PSScriptRoot
$ProjectRoot = Resolve-Path "$ScriptDir\.."
Set-Location $ProjectRoot

Clear-Host
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "   ENTERPRISE SERVER FACTORY - MASTER CONTROL"
Write-Host "   Root: $ProjectRoot"
Write-Host "=============================================" -ForegroundColor Cyan

# --- 2. ENVIRONMENT PREP (Global) ---
# Ensure Packer can find oscdimg for ISO creation (Critical for Layer 1)
$AdkPath = "$ProjectRoot\tools\Oscdimg"
if (Test-Path "$AdkPath\oscdimg.exe") {
    if ($env:Path -notlike "*$AdkPath*") {
        $env:Path = "$AdkPath;" + $env:Path
        Write-Host " [System] Added 'tools' to PATH for this session." -ForegroundColor Green
    }
} else {
    Write-Host " [WARNING] 'oscdimg.exe' not found at: $AdkPath" -ForegroundColor Yellow
    Write-Host "           Layer 1 build will fail if selected." -ForegroundColor Yellow
}

# --- 3. LAYER SELECTION ---
Write-Host "`nSelect Build Layer:"
Write-Host " [1] Layer 1: Base Image (ISO -> Raw VHDX)"
Write-Host " [2] Layer 2: Patching (Raw VHDX -> Golden Image)"
Write-Host " [3] Layer 3: Deployment (Golden Image -> Production VM)"
$Layer = Read-Host " Enter Option [1-3]"

switch ($Layer) {
    "1" {
        # --- LAYER 1: BASE ---
        Write-Host "`n[Layer 1] Building Base Image..." -ForegroundColor Cyan
        
        # Check ISO
        if (-not (Test-Path "ISO\WS2022.iso")) {
            Write-Error "ISO not found! Please place 'WS2022.iso' in the '\ISO' folder."
            exit
        }

        # Initialize (Local only)
        # Note: We do NOT use 'packer init' because individual files are self-contained.
        # Running 'packer init .' on the root would cause the "Duplicate Plugin" error.
        # Instead, we rely on Packer auto-downloading plugins or a prior manual init if needed.
        # If 'packer init' is strictly required, it must be run against the specific file, 
        # but 'packer init file.pkr.hcl' is not valid syntax. 
        # WORKAROUND: We assume plugins are installed. If not, user must run 'packer init 1-base.pkr.hcl' manually.
        
        $PackerCmd = ".\packer.exe build -force 1-base.pkr.hcl"
        Invoke-Expression $PackerCmd
    }

    "2" {
        # --- LAYER 2: PATCHING ---
        Write-Host "`n[Layer 2] Patching Base Image..." -ForegroundColor Cyan
        
        # Check for Base Image
        if (-not (Test-Path "builds\base")) {
            Write-Warning "Base build directory not found. Did Layer 1 complete?"
        }

        $PackerCmd = ".\packer.exe build -force 2-patch.pkr.hcl"
        Invoke-Expression $PackerCmd
    }

    "3" {
        # --- LAYER 3: DEPLOYMENT (Existing Logic) ---
        Write-Host "`n[Layer 3] Configuring Deployment..." -ForegroundColor Cyan

        # 3a. Configuration Inputs
        $VMName = Read-Host "    Hostname (Default: Server2022-L3)"
        if ([string]::IsNullOrWhiteSpace($VMName)) { $VMName = "Server2022-L3" }

        $CPU = Read-Host "    vCPU (Default: 2. Options: 2, 4, 8, 12)"
        if ([string]::IsNullOrWhiteSpace($CPU)) { $CPU = "2" }

        $RAM = Read-Host "    RAM MB (Default: 4096. Options: 2048, 4096, 8192, 16384)"
        if ([string]::IsNullOrWhiteSpace($RAM)) { $RAM = "4096" }

        # 3b. Switch Selection
        Write-Host "`n    Network Configuration:"
        $Switches = Get-VMSwitch | Select-Object Name
        $SwitchName = "Default Switch" # Fallback

        if ($Switches.Count -eq 1) {
            $SwitchName = $Switches[0].Name
            Write-Host "    Found single switch: '$SwitchName'. Using automatically." -ForegroundColor Gray
        }
        elseif ($Switches.Count -gt 1) {
            $i = 0
            foreach ($Sw in $Switches) {
                $i++
                Write-Host "    [$i] $($Sw.Name)"
            }
            $Selection = Read-Host "    Select Switch [1-$($Switches.Count)] (Default: Default Switch)"
            if ([int]::TryParse($Selection, [ref]$null) -and $Selection -le $Switches.Count -and $Selection -gt 0) {
                $SwitchName = $Switches[$Selection-1].Name
            }
        }
        Write-Host "    Target Switch: $SwitchName" -ForegroundColor Green

        # 3c. Role Selection
        Write-Host "`n    Select Server Role:"
        Write-Host "    [1] Web  [2] DC  [3] File  [4] RDS  [5] Container  [6] Mgmt  [7] Generic"
        $RoleInput = Read-Host "    Select Option"
        $Role = switch ($RoleInput) { 
            "1" {"Web"} "2" {"DC"} "3" {"FileServer"} "4" {"RDS"} "5" {"ContainerHost"} "6" {"Mgmt"} Default {"Generic"} 
        }

        # 3d. Build Execution
        Write-Host "`n[Action] Building Artifact ($Role)..." -ForegroundColor Cyan
        
        if (-not (Test-Path ".\packer.exe")) {
            Write-Error "Packer.exe not found in Project Root ($ProjectRoot)!"
            exit
        }

        $PackerCmd = ".\packer.exe build -force -var 'role=$Role' -var 'vm_name=$VMName' -var 'vm_cpu=$CPU' -var 'vm_ram=$RAM' -var 'switch_name=$SwitchName' 3-deploy.pkr.hcl"
        Invoke-Expression $PackerCmd

        # 3e. Auto-Import
        if ($LASTEXITCODE -eq 0) {
            $BuildDir = "$ProjectRoot\builds\deploy-$VMName"
            $VMCX = Get-ChildItem $BuildDir -Recurse -Filter "*.vmcx" | Select-Object -First 1
            
            if ($VMCX) {
                Write-Host "`n[Hyper-V] Importing VM..." -ForegroundColor Yellow
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
    }

    Default {
        Write-Warning "Invalid selection. Exiting."
    }
}