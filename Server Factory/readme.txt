Server Factory: Hyper-V Automation Pipeline

Version: 3.6 (Modular Engine Edition)

A fully automated, "Opt-In" configuration factory that transforms a raw Windows Server 2022 ISO into a production-ready, secure, and role-specific Virtual Machine artifact.

🚀 Key Features

4-Layer Architecture: Decouples the OS, Patching, Software Installation, and Runtime Configuration for maximum speed and modularity.

Interactive Build Wrapper: A menu-driven PowerShell script (build.ps1) handles CPU, RAM, Network, and Role selection—no code editing required.

"Opt-In" Security: The runtime engine detects roles (IIS, RDS, etc.) but prompts you before applying hardening or security constraints. Nothing breaks silently.

Self-Healing Logic: If Sysprep strips critical features (like Containers or Hyper-V), the runtime engine detects the mismatch against the Registry and automatically repairs the VM on first boot.

Dynamic Networking: Automatically detects and lists your Hyper-V switches.

🛠️ The 4 Layers

Layer 1 (Base): Installs the raw OS from ISO. Enables WinRM and basic networking.

Layer 2 (Patching): Runs a rigorous 3-Pass Windows Update cycle to create a fully patched "Golden Image".

Layer 3 (Factory): Installs role binaries (IIS, AD-DS, Containers) and stamps the Registry with the intended role and hostname to survive Sysprep.

Layer 4 (Runtime): A "Day 0" wizard (RuntimeWizard.ps1) that runs inside the final VM to handle:

Identity (Hostname persistence)

Network (Static IP for DCs, DNS Pre-Flight checks)

Role Configuration (AppPools, FSRM Screens, RDS Timeouts)

Security Hardening (Opt-In)

📋 Prerequisites

Hyper-V: Enabled on the host machine.

Packer: packer.exe must be in the project root.

ISO File: A Windows Server 2022 ISO placed in \ISO and named WS2022.iso.

Note: Ensure the 1-base.pkr.hcl file points to this path.

Oscdimg: The folder tools\Oscdimg must contain oscdimg.exe (required to build the boot ISO).

📂 Folder Structure

Ensure your project looks like this:

/ (Project Root)
├── packer.exe              # HashiCorp Packer binary
├── 1-base.pkr.hcl          # Layer 1 Template
├── 2-patch.pkr.hcl         # Layer 2 Template
├── 3-deploy.pkr.hcl        # Layer 3 Template
├── Autounattend.xml        # Boot Answer File
├── Unattend.xml            # Sysprep Answer File
│
├── ISO/
│   └── WS2022.iso          # [REQUIRED] Your Source ISO
│
├── scripts/
│   ├── build.ps1           # <--- RUN THIS TO START
│   ├── update.ps1          # Patching Logic
│   ├── deploy-config.ps1   # Layer 3 Role Injection
│   └── RuntimeWizard.ps1   # Layer 4 Configuration Engine
│
└── tools/
    └── Oscdimg/
        └── oscdimg.exe     # [REQUIRED] ISO Creation Tool


🎮 How to Use (Step-by-Step)

1. Start the Factory

Open PowerShell as Administrator, navigate to the folder, and run:

.\scripts\build.ps1


2. Configure Hardware

The script will prompt you for VM specs.

Hostname: Enter target name (e.g., WEB01).

vCPU: Select 2, 4, 8, or 12.

RAM: Select 2048, 4096, 8192, or 16384 MB.

3. Select Network

The script scans your Hyper-V switches. Select the one you want the VM to use (e.g., "Default Switch" or "External").

4. Select Role

Choose the server's purpose. This determines which binaries are installed in Layer 3.

[1] Web: IIS, Management Tools.

[2] DC: AD-DS, DNS, GPMC.

[3] File: File Server, FSRM (Resource Manager).

[4] RDS: Remote Desktop Session Host.

[5] Container: Hyper-V, Containers, Docker preparation.

[6] Mgmt: RSAT Tools only.

5. Build & Import

Packer will take over. It will:

Clone the Golden Image.

Inject the Role binaries.

Seed the Registry (HKLM:\Software\ServerFactory) with the Identity and Role.

Sysprep and Shutdown.

Auto-Import: The script will automatically import the new VM into Hyper-V and start it.

6. Runtime Configuration (The "Wizard")

Open the VM Console in Hyper-V.

Log in (Administrator / P@ssw0rd123!).

The Runtime Wizard will launch automatically.

Follow the prompts to:

Verify Hostname (Auto-reboot if mismatch).

Configure Network (Static IP for DCs).

Role Setup: (e.g., "IIS Detected. Remove Server Headers? [Y/N]").

Domain Join: The wizard performs a DNS check before attempting to join.

❓ Troubleshooting

"Role not detected" in Runtime Wizard?

The Wizard relies on the Registry key HKLM:\Software\ServerFactory\ServerRole to know what it is supposed to be.

If Sysprep stripped the Windows Feature (common with Containers), the Wizard's Self-Healing logic will read the Registry, reinstall the missing feature, and reboot automatically to fix it.

Packer fails with "switch_name" error?

Ensure you are running the build via scripts\build.ps1. Running packer build manually requires you to pass the -var 'switch_name=...' argument yourself.

Update Cycle Stuck?

The update.ps1 script creates a local log at C:\Logs\Update_Cycle.log inside the VM. Check this log if the process seems frozen.