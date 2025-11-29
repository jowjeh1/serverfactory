packer {
  required_plugins {
    hyperv = {
      source  = "github.com/hashicorp/hyperv"
      version = ">= 1.0.0"
    }
  }
}

source "hyperv-iso" "base" {
  # --- INPUTS ---
  iso_url        = "C:\\Packer-Demo\\ISO\\WS2022.iso"
  iso_checksum   = "none"
  switch_name    = "Default Switch"
  
  # --- VM SPECS ---
  vm_name        = "Server2022-Base-Raw"
  disk_size      = 61440
  memory         = 4096
  cpus           = 2
  generation     = 2
  enable_secure_boot = false
  
  # --- OUTPUT ---
  output_directory = "builds/base"

  # --- WINRM ---
  communicator   = "winrm"
  winrm_username = "Administrator"
  winrm_password = "P@ssw0rd123!"
  winrm_timeout  = "30m"
  winrm_insecure = true
  
  # --- BOOT ---
  headless       = false
  cd_files       = ["Autounattend.xml"]
  
  # --- SHUTDOWN STRATEGY ---
  # Packer runs this command automatically AFTER provisioning is done.
  # This shuts down the VM gracefully so Packer can export the VHDX.
  shutdown_command = "shutdown /s /t 10 /f /d p:4:1"
  shutdown_timeout = "30m"
}

build {
  sources = ["source.hyperv-iso.base"]

  # 1. Setup WinRM (Standard)
  provisioner "powershell" {
    inline = [
      "winrm quickconfig -q",
      "Set-Service -Name WinRM -StartupType Automatic -Status Running"
    ]
  }

  # REMOVED: The manual shutdown script. 
  # We let the 'shutdown_command' above handle it automatically.
}