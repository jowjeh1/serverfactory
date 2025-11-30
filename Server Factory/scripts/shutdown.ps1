# scripts/shutdown.ps1
# Just shut down the VM so Packer can save the state.
# DO NOT RUN SYSPREP HERE. We need the user/password to persist for the next build.

Write-Host "Stopping computer for Base Image capture..."
Stop-Computer -Force