Server Factory: Hyper-V Automation Pipeline

Version: 3.7 (Master Wrapper Edition)

A fully automated, "Opt-In" configuration factory that transforms a raw Windows Server 2022 ISO into a production-ready, secure, and role-specific Virtual Machine artifact.

🚀 Key Features

Master Build Wrapper: A single menu-driven script (scripts\build.ps1) manages the entire lifecycle—from ISO to Base Image (Layer 1), Patching (Layer 2), and final Deployment (Layer 3).

4-Layer Architecture: Decouples the OS, Patching, Software Installation, and Runtime Configuration for maximum speed and modularity.

"Opt-In" Security: The runtime engine detects roles (IIS, RDS, etc.) but prompts you before applying hardening or security constraints. Nothing breaks silently.

Self-Healing Logic: If Sysprep strips critical features (like Containers or Hyper-V), the runtime engine detects the mismatch against the Registry Intent and automatically repairs the VM on first boot.

Dynamic Networking: Automatically detects and lists your Hyper-V switches during deployment.

🛠️ The 4 Layers

Layer 1 (Base): Installs the raw OS from ISO. Enables WinRM and basic networking.

Trigger: build.ps1 -> Option [1]

Layer 2 (Patching): Runs a rigorous 3-Pass Windows Update cycle to create a fully patched "Golden Image".

Trigger: build.ps1 -> Option [2]

Layer 3 (Factory): Installs role binaries (IIS, AD-DS, Containers) and stamps the Registry with the intended role and hostname to survive Sysprep.

Trigger: build.ps1 -> Option [3]

Layer 4 (Runtime): A "Day 0" wizard (RuntimeWizard.ps1) that runs inside the final VM to handle:

Identity (Hostname persistence)

Network (Static IP for DCs, DNS Pre-Flight checks)

Role Configuration (AppPools, FSRM Screens, RDS Timeouts)

Hardware Validation (Checks for Nested Virtualization support for Containers)

📋 Prerequisites

Hyper-V: Enabled on the host machine.

Packer: packer.exe must be in the project root.

ISO File: A Windows Server 2022 ISO placed in \ISO and named WS2022.iso.

Oscdimg: The folder tools\Oscdimg must contain oscdimg.exe (required for Layer 1 ISO creation).

📂 Folder Structure

Ensure your project looks like this:

/ (Project Root)
├── packer.exe              # HashiCorp Packer binary
├── 1-base.pkr.hcl          # Layer 1 Template (Self-contained)
├── 2-patch.pkr.hcl         # Layer 2 Template (Self-contained)
├── 3-deploy.pkr.hcl        # Layer 3 Template (Self-contained)
├── Autounattend.xml        # Boot Answer File
├── Unattend.xml            # Sysprep Answer File
│
├── ISO/
│   └── WS2022.iso          # [REQUIRED] Your Source ISO
│
├── scripts/
│   ├── build.ps1           # <--- MASTER WRAPPER (Run this!)
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


2. Select Build Layer

The script now acts as a master controller. Select the stage you want to run:

[1] Layer 1: Builds the Base VHDX from the ISO. (Ensures Oscdimg is in PATH).

[2] Layer 2: Applies Windows Updates to the Base VHDX.

[3] Layer 3: Deploys a final VM from the Golden Image.

3. Layer 3 Deployment Flow

If you select Option [3], follow these prompts:

Hostname: Enter target name (e.g., WEB01).

Hardware: Select vCPU (2-12) and RAM (2GB-16GB).

Network: Select the target Hyper-V switch.

Role: Choose the server's purpose (Web, DC, File, RDS, Container, Mgmt).

4. Build & Import

Packer will clone the Golden Image, inject binaries, Seed the Registry, Sysprep, and auto-import the VM into Hyper-V.

5. Runtime Configuration (The "Wizard")

Open the VM Console in Hyper-V.

Log in (Administrator / P@ssw0rd123!).

The Runtime Wizard will launch automatically.

Follow the interactive prompts for final configuration.

❓ Troubleshooting

"Role not detected" in Runtime Wizard?

The Wizard relies on HKLM:\Software\ServerFactory\ServerRole. If Sysprep stripped the feature (e.g., Containers), the Wizard's Self-Healing logic will reinstall it and reboot.

Note: If the underlying hardware does not support Hyper-V (Nested Virtualization), the Wizard will gracefully skip the Container setup to prevent a reboot loop.

Packer "Duplicate Plugin" error?

Do not run packer init . on the root folder. Each .pkr.hcl file is self-contained. Use the build.ps1 wrapper, or run packer init <filename> specifically if needed.

Layer 1 fails with "ISO creation command not found"?

Ensure you are running via scripts\build.ps1. The script automatically adds tools\Oscdimg to the session PATH so Packer can find the utility.