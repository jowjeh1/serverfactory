variable "role" { type = string }
variable "vm_name" { type = string }

# UPDATED: Validation for CPU
variable "vm_cpu" { 
  type = number
  validation {
    condition     = contains([2, 4, 8, 12], var.vm_cpu)
    error_message = "The vm_cpu value must be one of: 2, 4, 8, 12."
  }
}

# UPDATED: Validation for RAM
variable "vm_ram" { 
  type = number 
  validation {
    condition     = contains([2048, 4096, 8192, 16384], var.vm_ram)
    error_message = "The vm_ram value must be one of: 2048, 4096, 8192, 16384."
  }
}

variable "switch_name" { 
  type    = string 
  default = "Default Switch" 
}

source "hyperv-vmcx" "deploy" {
  # --- DYNAMIC PATHS ---
  clone_from_vmcx_path = "${path.root}/builds/golden"
  
  output_directory = "builds/deploy-${var.vm_name}"
  vm_name          = "${var.vm_name}"
  cpus             = var.vm_cpu
  memory           = var.vm_ram
  switch_name      = var.switch_name
  headless         = false
  
  communicator   = "winrm"
  winrm_username = "Administrator"
  winrm_password = "P@ssw0rd123!"
  winrm_timeout  = "30m"
  winrm_insecure = true
  
  cd_content = { "Unattend.xml" = file("Unattend.xml") }
  
  shutdown_command = "C:\\Windows\\System32\\Sysprep\\sysprep.exe /generalize /oobe /shutdown /quiet /mode:vm"
  shutdown_timeout = "60m"
}

build {
  sources = ["source.hyperv-vmcx.deploy"]
  
  provisioner "powershell" {
    environment_vars = ["SERVER_ROLE=${var.role}", "VM_NAME=${var.vm_name}"]
    script = "scripts/deploy-config.ps1"
  }
  
  provisioner "file" { 
    source      = "scripts/RuntimeWizard.ps1" 
    destination = "C:\\Users\\Public\\Desktop\\RuntimeWizard.ps1" 
  }
  
  provisioner "file" { 
    source      = "scripts/runtime_config.json" 
    destination = "C:\\Users\\Public\\Desktop\\runtime_config.json" 
  }
  
  provisioner "powershell" {
    inline = [
      "$C='@powershell -NoProfile -ExecutionPolicy Bypass -File C:\\Users\\Public\\Desktop\\RuntimeWizard.ps1'",
      "Set-Content -Path 'C:\\Users\\Public\\Desktop\\Start-Wizard.cmd' -Value $C"
    ]
  }
  
  provisioner "windows-restart" { restart_timeout = "30m" }
}