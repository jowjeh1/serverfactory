Server Factory: Hyper-V Automation Pipeline
A fully automated "Factory" that turns a Windows Server 2022 ISO into a secure, patched, and configured Virtual Machine artifact.
📂 Folder Structure
This project is portable. You can place it anywhere (e.g., C:\ServerFactory or D:\DevOps), provided you maintain this internal structure:
/ (Project Root)
├── packer.exe              # HashiCorp Packer binary
├── 1-base.pkr.hcl          # Layer 1: ISO -> Raw VHDX
├── 2-patch.pkr.hcl         # Layer 2: Raw -> Patched Golden Image
├── 3-deploy.pkr.hcl        # Layer 3: Golden -> Role-Based VM
├── Autounattend.xml        # Answer file for Layer 1
├── Unattend.xml            # Answer file for Layer 3
│
├── ISO/
│   └── WS2022.iso          # YOU MUST PROVIDE THIS FILE
│
├── builds/                 # Output directory for artifacts (Auto-created)
│
├── scripts/
│   ├── build.ps1           # <--- RUN THIS SCRIPT TO START
│   ├── update.ps1          # Windows Update logic
│   └── RuntimeWizard.ps1   # Layer 4 Configuration Engine
│
└── tools/
    └── Oscdimg/
        └── oscdimg.exe     # Required for creating ISOs
🚀 How to Use
Prerequisites:
Enable Hyper-V on your machine.
Place your Windows Server 2022 ISO in the ISO/ folder and rename it to WS2022.iso (or update 1-base.pkr.hcl).
Ensure tools/Oscdimg/oscdimg.exe exists.
Run the Factory:Open PowerShell as Administrator.
Run the build wrapper:.\scripts\build.ps1
Follow the Menu:
The script will set up the environment paths automatically.
Enter your desired Hostname and select a Role (e.g., Web, DC).
The VM will be built, imported into Hyper-V, and started automatically.
Runtime (Layer 4):Open the VM console in Hyper-V.
The Runtime Wizard will launch automatically to finalize the configuration (IP, Domain Join, Security).
🛠️ The Layers
Layer 1 (Base): Installs OS from ISO.
Layer 2 (Patching): Applies Windows Updates (3 Passes) and creates the "Golden Image".
Layer 3 (Factory): Installs binaries (IIS, AD-DS, etc.) and sets up the Runtime environment.
Layer 4 (Runtime): Runs inside the final VM to apply identity and security settings.