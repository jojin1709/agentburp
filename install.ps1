# ==============================================================================
# agentburp — Automated Windows User-Space Installer
# Developed by JOJIN JOHN
# Safe execution from any directory (including C:\Windows\System32)
# ==============================================================================

$ErrorActionPreference = "Stop"

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "   agentburp - Windows Automated Installer        " -ForegroundColor Cyan
Write-Host "   Developed by JOJIN JOHN                        " -ForegroundColor White
Write-Host "==================================================" -ForegroundColor Cyan

$InstallDir = [System.IO.Path]::Combine($env:LOCALAPPDATA, "Programs", "agentburp")
$ExePath = [System.IO.Path]::Combine($InstallDir, "agentburp.exe")
$ScopePath = [System.IO.Path]::Combine($InstallDir, "scope.yml")

Write-Host "[1/4] Preparing installation directory: $InstallDir" -ForegroundColor Gray
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
}

Write-Host "[2/4] Downloading agentburp.exe..." -ForegroundColor Yellow
$ExeUrl = "https://github.com/jojin1709/agentburp/releases/latest/download/agentburp.exe"
Invoke-RestMethod -Uri $ExeUrl -OutFile $ExePath

Write-Host "[3/4] Downloading default scope.yml..." -ForegroundColor Yellow
$ScopeUrl = "https://raw.githubusercontent.com/jojin1709/agentburp/main/examples/scope.yml"
Invoke-RestMethod -Uri $ScopeUrl -OutFile $ScopePath

Write-Host "[4/4] Configuring User PATH environment variable..." -ForegroundColor Yellow
$UserPath = [Environment]::GetEnvironmentVariable("PATH", "User")
if ($UserPath -notlike "*$InstallDir*") {
    if ($UserPath) {
        $NewPath = "$UserPath;$InstallDir"
    } else {
        $NewPath = $InstallDir
    }
    [Environment]::SetEnvironmentVariable("PATH", $NewPath, "User")
    $env:PATH += ";$InstallDir"
    Write-Host "[OK] Added $InstallDir to user PATH." -ForegroundColor Green
} else {
    Write-Host "[OK] $InstallDir is already in user PATH." -ForegroundColor Green
}

Write-Host ""
Write-Host "[SUCCESS] agentburp has been installed successfully!" -ForegroundColor Green
Write-Host "Installed location: $ExePath" -ForegroundColor White
Write-Host "You can now run 'agentburp' from any terminal." -ForegroundColor Cyan
Write-Host ""

& "$ExePath" --help
