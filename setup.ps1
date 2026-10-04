# setup.ps1 — Run inside Windows 11 VM as Admin
# Installs deps and launches VMDetect

Write-Host "[*] Installing Python deps..." -ForegroundColor Cyan
pip install rich wmi pywin32 psutil

Write-Host "[*] Running VMDetect..." -ForegroundColor Cyan
python vmdetect.py
