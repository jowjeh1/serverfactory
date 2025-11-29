# post-config.ps1
# Final Cleanup and Sysprep for Golden Image
# This script ensures the image is generic, clean, and ready for cloning.

Write-Host "--- STARTING FINAL GOLDEN IMAGE PREPARATION ---"

# --- 1. CLEANUP ---
Write-Host "Performing final system cleanup..."

# Remove temp files to save space
Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue

# Clear Event Logs so the new VM starts fresh
Write-Host "Clearing Event Logs..."
Clear-EventLog -LogName Application, Security, System

# --- 2. SYSPREP & SHUTDOWN ---
# This generalizes the image (removes SIDs/Hardware IDs) and shuts down.
# This is mandatory for a Golden Image so it can be deployed to multiple servers.
Write-Host "Running Sysprep and shutting down the VM..."
& "C:\Windows\System32\Sysprep\sysprep.exe" /generalize /oobe /shutdown /quiet

Write-Host "--- END OF CONFIGURATION ---"