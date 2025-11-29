packer {
  required_plugins {
    hyperv = {
      source  = "github.com/hashicorp/hyperv"
      version = ">= 1.0.0"
    }
  }
}

# NOTE: We use "hyperv-vmcx" builder to clone an existing VM
source "hyperv-vmcx" "patch" {
  # --- INPUT ---
  clone_from_vmcx_path = "C:\\Packer-Demo\\builds\\base"
  
  # --- OUTPUT ---
  vm_name          = "Server2022-Golden-Patched"
  output_directory = "builds/golden"
  switch_name      = "Default Switch"
  
  # --- HEADLESS MODE ---
  headless         = false

  # --- WINRM ---
  communicator   = "winrm"
  winrm_username = "Administrator"
  winrm_password = "P@ssw0rd123!"
  winrm_timeout  = "30m"
  winrm_insecure = true
  
  # --- SHUTDOWN STRATEGY ---
  shutdown_command = "C:\\Windows\\System32\\Sysprep\\sysprep.exe /generalize /oobe /shutdown /quiet /mode:vm"
  shutdown_timeout = "60m"
}

build {
  sources = ["source.hyperv-vmcx.patch"]

  # --- PASS 1: CRITICAL / SERVICING STACK UPDATES ---
  provisioner "powershell" {
    script = "scripts/update.ps1"
    elevated_user     = "Administrator"
    elevated_password = "P@ssw0rd123!"
  }
  provisioner "windows-restart" { restart_timeout = "30m" }

  # --- PASS 2: CUMULATIVE UPDATES ---
  provisioner "powershell" {
    # Added 2m pause to allow Windows Update service to stabilize after reboot
    pause_before = "2m"
    script = "scripts/update.ps1"
    elevated_user     = "Administrator"
    elevated_password = "P@ssw0rd123!"
  }
  provisioner "windows-restart" { restart_timeout = "30m" }

  # --- PASS 3: .NET / DRIVERS / OPTIONAL ---
  provisioner "powershell" {
    pause_before = "2m"
    script = "scripts/update.ps1"
    elevated_user     = "Administrator"
    elevated_password = "P@ssw0rd123!"
  }
  provisioner "windows-restart" { restart_timeout = "30m" }

  # --- PASS 4: FINAL CHECK (Should be 0 Updates) ---
  provisioner "powershell" {
    pause_before = "2m"
    script = "scripts/update.ps1"
    elevated_user     = "Administrator"
    elevated_password = "P@ssw0rd123!"
  }
  provisioner "windows-restart" { restart_timeout = "30m" }

  # --- FINAL CLEANUP & SYSPREP ---
  provisioner "powershell" {
    inline = [
      "Write-Host '--- Starting Final Cleanup ---'",
      "Write-Host 'Cleaning up temp files...'",
      "Remove-Item -Path $env:TEMP\\* -Recurse -Force -ErrorAction SilentlyContinue",
      "Clear-EventLog -LogName Application, Security, System",
      "Write-Host 'Cleanup complete. Packer will now run Sysprep to shutdown.'"
    ]
  }
}