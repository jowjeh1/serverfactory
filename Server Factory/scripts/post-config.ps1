# post-config.ps1

Write-Host "--- STARTING POST-INSTALL CONFIGURATION ---"

# --- PROOF STEP 1: Create a file to prove this script ran ---
$ProofFilePath = "C:\Post_Config_Success.txt"
$Content = "Packer provisioning script ran successfully on $(Get-Date)."

Write-Host "Creating proof file: $ProofFilePath"
Out-File -FilePath $ProofFilePath -InputObject $Content -Encoding UTF8

# --- PROOF STEP 2: Create a simple local user and feature installation ---
Write-Host "Installing Web Server (IIS) feature..."
Install-WindowsFeature -Name Web-Server -Confirm:$false

Write-Host "Creating local 'packer_svc' user..."
net user packer_svc P@ckerSvc /add /y

# --- FINAL STEP: Run Sysprep to generalize and shut down ---
# This step is critical for a template. It prepares the VHDX for deployment.
Write-Host "Running Sysprep and shutting down the VM. Build complete!"
& "C:\Windows\System32\Sysprep\sysprep.exe" /generalize /oobe /shutdown

Write-Host "--- END OF CONFIGURATION ---"