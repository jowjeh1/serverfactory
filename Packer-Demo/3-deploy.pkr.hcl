packer {
  required_plugins {
    hyperv = {
      source  = "github.com/hashicorp/hyperv"
      version = ">= 1.0.0"
    }
  }
}

# --- INPUT VARIABLES ---
variable "role" {
  type        = string
  description = "The server role to configure."
  validation {
    condition     = contains(["Web", "DC", "FileServer", "RDS", "ContainerHost", "Mgmt", "Generic"], var.role)
    error_message = "Role not supported. Check build.ps1 menu."
  }
}

variable "vm_name" {
  type        = string
  description = "The Hostname for the new VM"
}

variable "vm_ram" {
  type        = number
  description = "RAM in MB"
  validation {
    condition     = contains([2048, 4096, 8192, 16384], var.vm_ram)
    error_message = "RAM must be standard: 2048, 4096, 8192, 16384."
  }
}

variable "vm_cpu" {
  type        = number
  description = "CPU Cores"
  validation {
    condition     = contains([2, 4, 8], var.vm_cpu)
    error_message = "CPU must be 2, 4, or 8."
  }
}

# --- SOURCE ---
source "hyperv-vmcx" "deploy" {
  # CRITICAL FIX: Point to the root artifact folder created by the Layer 2 export.
  # This relies on the builder finding the .vmcx file recursively.
  clone_from_vmcx_path = "C:\\Packer-Demo\\builds\\golden" 
  output_directory     = "builds/deploy-${var.vm_name}"
  vm_name              = "${var.vm_name}"
  
  cpus   = var.vm_cpu
  memory = var.vm_ram
  
  switch_name    = "Default Switch"
  headless       = false
  
  communicator   = "winrm"
  winrm_username = "Administrator"
  winrm_password = "P@ssw0rd123!"
  winrm_timeout  = "30m"
  winrm_insecure = true
  
  cd_content = {
    "Unattend.xml" = file("Unattend.xml")
  }
  
  shutdown_command = "C:\\Windows\\System32\\Sysprep\\sysprep.exe /generalize /oobe /shutdown /quiet /mode:vm"
  shutdown_timeout = "60m"
}

# --- BUILD ---
build {
  sources = ["source.hyperv-vmcx.deploy"]

  # 1. Install Binaries (Layer 3 Logic)
  provisioner "powershell" {
    environment_vars = [
      "SERVER_ROLE=${var.role}",
      "VM_NAME=${var.vm_name}"
    ]
    script = "scripts/deploy-config.ps1"
  }

  # 2. Upload Runtime Wizard (Layer 4 Logic)
  provisioner "file" {
    source      = "scripts/RuntimeWizard.ps1"
    destination = "C:\\Users\\Public\\Desktop\\RuntimeWizard.ps1"
  }

  # 3. Upload Configuration File
  provisioner "file" {
    source      = "scripts/runtime_config.json"
    destination = "C:\\Users\\Public\\Desktop\\runtime_config.json"
  }

  # 4. Create "Double Click" Launcher
  provisioner "powershell" {
    inline = [
      "Write-Host 'Creating Wizard Launcher...'",
      "$Path = 'C:\\Users\\Public\\Desktop\\Start-Wizard.cmd'",
      "$Command = '@powershell -NoProfile -ExecutionPolicy Bypass -File C:\\Users\\Public\\Desktop\\RuntimeWizard.ps1'",
      "Set-Content -Path $Path -Value $Command"
    ]
  }

  # 5. Reboot to clear pending operations before Sysprep
  provisioner "windows-restart" {
    restart_timeout = "30m"
  }
}