@echo off
REM Build vmdetect.exe — run this inside Windows
echo [*] Installing deps...
pip install -r requirements.txt pyinstaller

echo [*] Building standalone .exe...
pyinstaller --onefile --console ^
  --name vmdetect ^
  --hidden-import wmi ^
  --hidden-import win32api ^
  --hidden-import win32con ^
  vmdetect.py

echo [*] Done.  dist\vmdetect.exe
pause
