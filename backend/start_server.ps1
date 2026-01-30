# ============================================================================
# Hybrid IDS Backend Startup Script (PowerShell)
# Uses the 'back' virtual environment
# ============================================================================

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "                   HYBRID IDS INFERENCE BACKEND SERVER" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host ""

# Get script directory
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

# Define venv Python path
$VenvPython = Join-Path $ScriptDir ".venv\Scripts\python.exe"

if (Test-Path $VenvPython) {
    Write-Host "[*] Using virtual environment: .venv" -ForegroundColor Green
    Write-Host "[*] Python: $VenvPython" -ForegroundColor Green
} else {
    Write-Host "[!] ERROR: Virtual environment '.venv' not found!" -ForegroundColor Red
    Write-Host "[!] Expected: $VenvPython" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host ""
Write-Host "[*] Starting FastAPI server on http://localhost:8000" -ForegroundColor Yellow
Write-Host "[*] API Documentation: http://localhost:8000/docs" -ForegroundColor Yellow
Write-Host "[*] Press Ctrl+C to stop the server" -ForegroundColor Yellow
Write-Host ""
Write-Host "================================================================================" -ForegroundColor Cyan

# Run uvicorn using the venv Python
& $VenvPython -m uvicorn app:app --host 0.0.0.0 --port 8000 --reload
