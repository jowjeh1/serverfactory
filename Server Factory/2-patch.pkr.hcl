source "hyperv-vmcx" "patch" {
  # --- DYNAMIC PATHS ---
  # Uses ${path.root} to find the base image in the current project folder
  clone_from_vmcx_path = "${path.root}/builds/base"
  
  vm_name          = "Server2022-Golden-Patched"
  output_directory = "builds/golden"
  switch_name      = "Default Switch"
  headless         = false
  
  communicator   = "winrm"
  winrm_username = "Administrator"
  winrm_password = "P@ssw0rd123!"
  winrm_timeout  = "30m"
  winrm_insecure = true
  
  shutdown_command = "C:\\Windows\\System32\\Sysprep\\sysprep.exe /generalize /oobe /shutdown /quiet /mode:vm"
  shutdown_timeout = "60m"
}

build {
  sources = ["source.hyperv-vmcx.patch"]

  # Pass 1: Critical Updates
  provisioner "powershell" {
    script            = "scripts/update.ps1"
    elevated_user     = "Administrator"
    elevated_password = "P@ssw0rd123!"
  }
  provisioner "windows-restart" { restart_timeout = "30m" }

  # Pass 2: Cumulative Updates
  provisioner "powershell" {
    pause_before      = "2m"
    script            = "scripts/update.ps1"
    elevated_user     = "Administrator"
    elevated_password = "P@ssw0rd123!"
  }
  provisioner "windows-restart" { restart_timeout = "30m" }

  # Pass 3: Final Sweep + CLEANUP
  # FIX: Packer 'powershell' provisioner does not support 'arguments'. 
  # We must upload the file first, then execute it with the switch inline.
  
  provisioner "file" {
    source      = "scripts/update.ps1"
    destination = "C:\\Windows\\Temp\\update.ps1"
  }

  provisioner "powershell" {
    pause_before      = "2m"
    inline            = ["& 'C:\\Windows\\Temp\\update.ps1' -Finalize"]
    elevated_user     = "Administrator"
    elevated_password = "P@ssw0rd123!"
  }

  provisioner "windows-restart" { restart_timeout = "30m" }

  # Generic System Cleanup (Event Logs / Temp)
  provisioner "powershell" {
    inline = [
      "Remove-Item -Path $env:TEMP\\* -Recurse -Force -EA 0",
      "Clear-EventLog -LogName Application, Security, System",
      # Clean up the script we uploaded in Pass 3
      "Remove-Item -Path 'C:\\Windows\\Temp\\update.ps1' -Force -ErrorAction SilentlyContinue"
    ]
  }
}