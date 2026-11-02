@echo off
setlocal EnableExtensions
cd /d "%~dp0"
echo ========================================
echo PharmaSys Backend - Manual Diagnostic
echo ========================================
echo.

powershell -NoProfile -ExecutionPolicy Bypass -Command "try { $r=Invoke-WebRequest -UseBasicParsing -Uri 'http://127.0.0.1:8000/health' -TimeoutSec 2; if ($r.StatusCode -eq 200) { Write-Host '[OK] Backend is already running.'; exit 0 } } catch {} ; exit 1" >nul 2>&1
if not errorlevel 1 (
  echo [OK] Backend is already running on http://127.0.0.1:8000
  echo.
  pause
  exit /b 0
)

if not exist ".env" (
  powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup_env.ps1"
  if errorlevel 1 goto fail
)
if not exist ".venv\Scripts\python.exe" (
  where py >nul 2>&1
  if errorlevel 1 goto fail
  py -3 -m venv .venv
  if errorlevel 1 goto fail
)
.venv\Scripts\python.exe -m pip install -r requirements.txt
if errorlevel 1 goto fail
.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
exit /b %ERRORLEVEL%
:fail
echo [ERROR] Backend setup failed.
pause
exit /b 1
