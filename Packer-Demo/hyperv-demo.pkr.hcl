# This file is the complete, modern HCL2 configuration.

packer {
  required_plugins {
    # Explicitly require the hyperv plugin
    hyperv = {
      source  = "github.com/hashicorp/hyperv"
      version = ">= 1.0.0"
    }
  }
  required_version = ">= 1.9.0"
}

# 1. FIXED: The builder type is "hyperv-iso", NOT "hyperv"
source "hyperv-iso" "windows-demo" {
  # --- REQUIRED UPDATES: Change these for your system ---
  iso_url        = "C:\\Packer-Demo\\ISO\\WS2022.iso" # <--- UPDATE THIS PATH
  iso_checksum   = "none" # FIXED: Checksum is required. "none" allows skipping check for local files.
  switch_name    = "Default Switch" 
  # ------------------------
  
  vm_name        = "packer-quick-demo-hcl2"
  
  # FIXED: disk_size must be a number in MB (60GB * 1024 = 61440)
  disk_size      = 61440
  
  memory         = 4096
  cpus           = 2
  
  # UPDATED: Set to false so you can WATCH the VM boot and debug issues visually
  headless       = false
  
  # --- GENERATION 2 CONFIGURATION ---
  generation     = 2
  # Secure Boot is usually disabled for templates to prevent driver signing headaches during build
  enable_secure_boot = false 
  
  # Credentials for WinRM (MUST match Autounattend.xml password)
  communicator   = "winrm"
  winrm_username = "Administrator"
  winrm_password = "P@ssw0rd123!"
  winrm_timeout  = "30m"
  winrm_insecure = true
  
  # --- GEN 2 USES CD_FILES (Requires xorriso or oscdimg) ---
  # This creates a secondary DVD drive with your answer file, as Gen 2 has no floppy support.
  cd_files       = ["Autounattend.xml"]
  
  # FIXED: Added shutdown command to resolve warning
  shutdown_command = "shutdown /s /t 10 /f /d p:4:1"
}

# 2. Define the build process
build {
  # FIXED: Reference the correct source type here too
  sources = ["source.hyperv-iso.windows-demo"]

  # Provisioner 1: Initial WinRM Setup
  provisioner "powershell" {
    inline = [
      "Write-Host 'Initial configuration started...'",
      "winrm quickconfig -q",
      "Set-Service -Name WinRM -StartupType Automatic -Status Running",
      "Start-Sleep -Seconds 15"
    ]
  }

  # Provisioner 2: Runs your script to install IIS and cleanup
  provisioner "powershell" {
    # FIXED: Updated path to look in the scripts folder
    script = "scripts/post-config.ps1"
  }
}