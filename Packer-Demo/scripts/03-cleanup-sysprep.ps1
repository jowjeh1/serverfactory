# 03-cleanup-sysprep.ps1 - Final cleanup and Sysprep

Write-Host "--- Starting 03-cleanup-sysprep.ps1: Finalization and Sysprep ---"

# Cleanup: Clear event logs and temporary files
Write-Host "Performing final system cleanup..."
Clear-EventLog -LogName Application, Security, System
Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue

# IMPORTANT: Run Sysprep to generalize the image and shut down
# /generalize: Strips unique identifiers (like SIDs)
# /oobe: Sets the VM to boot into the Out-of-Box Experience on first boot
# /shutdown: Shuts down the VM so Packer can capture the VHDX artifact
Write-Host "Running Sysprep. This will shut down the VM. Build complete!"
& "C:\Windows\System32\Sysprep\sysprep.exe" /generalize /oobe /shutdown

Write-Host "--- 03-cleanup-sysprep.ps1 End (VM is shutting down) ---"