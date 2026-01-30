@echo off
REM ============================================================================
REM Hybrid IDS Backend Startup Script
REM Uses the 'back' virtual environment
REM ============================================================================

echo ================================================================================
echo                    HYBRID IDS INFERENCE BACKEND SERVER
echo ================================================================================
echo.

cd /d "%~dp0"

REM Use the 'back' virtual environment Python directly
set VENV_PYTHON=%~dp0back\Scripts\python.exe

if exist "%VENV_PYTHON%" (
    echo [*] Using virtual environment: back
    echo [*] Python: %VENV_PYTHON%
) else (
    echo [!] ERROR: Virtual environment 'back' not found!
    echo [!] Expected: %VENV_PYTHON%
    pause
    exit /b 1
)

echo.
echo [*] Starting FastAPI server on http://localhost:8000
echo [*] API Documentation: http://localhost:8000/docs
echo [*] Press Ctrl+C to stop the server
echo.
echo ================================================================================

"%VENV_PYTHON%" -m uvicorn app:app --host 0.0.0.0 --port 8000 --reload

pause
