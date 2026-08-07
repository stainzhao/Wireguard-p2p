$ErrorActionPreference = "SilentlyContinue"
Stop-ScheduledTask -TaskName "WireGuard P2P Sync"
Unregister-ScheduledTask -TaskName "WireGuard P2P Sync" -Confirm:$false
Remove-Item "$env:ProgramData\WireGuardP2P\p2p_sync_windows.ps1" -Force
Remove-Item "$env:ProgramData\WireGuardP2P\state.json" -Force
Remove-Item "$env:ProgramData\WireGuardP2P\p2p_sync.log" -Force
Write-Host "Old PowerShell scheduled task removed."
