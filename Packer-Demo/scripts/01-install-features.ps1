# 01-install-features.ps1 - Initial Configuration

Write-Host "--- Starting 01-install-features.ps1: Basic OS configuration ---"

# PROOF: Install a simple role to confirm provisioning works
Write-Host "Installing Web Server (IIS) feature..."
Install-WindowsFeature -Name Web-Server -Confirm:$false

# PROOF: Create a file to prove this script ran
$ProofFilePath = "C:\Packer_Step1_Features_Installed.txt"
$Content = "Packer provisioning script 01 ran successfully on $(Get-Date)."
Out-File -FilePath $ProofFilePath -InputObject $Content -Encoding UTF8

Write-Host "--- 01-install-features.ps1 Complete ---"