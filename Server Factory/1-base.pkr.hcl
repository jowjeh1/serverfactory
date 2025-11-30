source "hyperv-iso" "base" {
  # --- DYNAMIC PATHS ---
  # ${path.root} refers to the folder containing this .hcl file
  iso_url        = "${path.root}/ISO/WS2022.iso"
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
  
  shutdown_command = "powershell -executionpolicy bypass -file scripts/shutdown.ps1"
  shutdown_timeout = "30m"
}

build {
  sources = ["source.hyperv-iso.base"]
  
  provisioner "powershell" {
    inline = [
      "winrm quickconfig -q",
      "Set-Service -Name WinRM -StartupType Automatic -Status Running"
    ]
  }
}