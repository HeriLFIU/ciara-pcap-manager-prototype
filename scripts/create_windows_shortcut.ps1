# Create Windows shortcuts (.lnk) for CIARA PCAP Analyzer on the Desktop and in the repository root.
$ErrorActionPreference = "Stop"

$WshShell = New-Object -ComObject WScript.Shell
$Desktop = [Environment]::GetFolderPath('Desktop')
$RepoRoot = Split-Path -Parent $PSScriptRoot
$TargetPath = Join-Path $RepoRoot "launch.bat"

# 1. Desktop shortcut
$DesktopShortcutPath = Join-Path $Desktop "CIARA PCAP Analyzer.lnk"
$Shortcut = $WshShell.CreateShortcut($DesktopShortcutPath)
$Shortcut.TargetPath = $TargetPath
$Shortcut.WorkingDirectory = $RepoRoot
$Shortcut.Description = "Launch CIARA PCAP Analyzer (Backend + GUI)"
$Shortcut.WindowStyle = 1 # Normal window (shows startup log, closes when GUI exits)
$Shortcut.Save()
Write-Host "Created Desktop shortcut: $DesktopShortcutPath"

# 2. Repository root shortcut
$RepoShortcutPath = Join-Path $RepoRoot "CIARA PCAP Analyzer.lnk"
$ShortcutRepo = $WshShell.CreateShortcut($RepoShortcutPath)
$ShortcutRepo.TargetPath = $TargetPath
$ShortcutRepo.WorkingDirectory = $RepoRoot
$ShortcutRepo.Description = "Launch CIARA PCAP Analyzer (Backend + GUI)"
$ShortcutRepo.WindowStyle = 1
$ShortcutRepo.Save()
Write-Host "Created Repository shortcut: $RepoShortcutPath"
