@echo off
setlocal enabledelayedexpansion

REM Default ports
set BACKEND_PORT=8000
set FRONTEND_PORT=5173

REM Parse command line arguments
:parse_args
if "%~1"=="" goto end_parse
if /i "%~1"=="--backend-port" (
    set BACKEND_PORT=%~2
    shift
    shift
    goto parse_args
)
if /i "%~1"=="--frontend-port" (
    set FRONTEND_PORT=%~2
    shift
    shift
    goto parse_args
)
if /i "%~1"=="-b" (
    set BACKEND_PORT=%~2
    shift
    shift
    goto parse_args
)
if /i "%~1"=="-f" (
    set FRONTEND_PORT=%~2
    shift
    shift
    goto parse_args
)
if /i "%~1"=="--help" (
    echo Usage: start.bat [options]
    echo.
    echo Options:
    echo   --backend-port, -b PORT    Backend server port (default: 8000)
    echo   --frontend-port, -f PORT   Frontend server port (default: 5173)
    echo   --help                     Show this help message
    echo.
    echo Examples:
    echo   start.bat
    echo   start.bat --backend-port 3000
    echo   start.bat -b 3000 -f 3001
    exit /b 0
)
shift
goto parse_args
:end_parse

echo =====================================================
echo   Aegis Threat v2.0
echo   NLP ^| Semantic Search ^| Attack Chains ^| Multi-LLM
echo =====================================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.8 or higher
    pause
    exit /b 1
)

REM Check if Node.js is installed
node --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Node.js is not installed or not in PATH
    echo Please install Node.js 18 or higher
    pause
    exit /b 1
)

echo [1/4] Checking dependencies...
echo.

REM Check if backend directory exists
if not exist "backend\app" (
    echo ERROR: Backend directory not found
    pause
    exit /b 1
)

REM Check if backend dependencies are installed (check for uvicorn)
pip show uvicorn >nul 2>&1
if errorlevel 1 (
    echo Installing backend dependencies...
    cd backend
    pip install -r requirements.txt
    if errorlevel 1 (
        echo ERROR: Failed to install backend dependencies
        cd ..
        pause
        exit /b 1
    )
    cd ..
)

REM Check if frontend dependencies are installed
if not exist "node_modules" (
    echo Installing frontend dependencies...
    call npm install
    if errorlevel 1 (
        echo ERROR: Failed to install frontend dependencies
        pause
        exit /b 1
    )
)

echo Port Configuration:
echo   Backend Port:  %BACKEND_PORT%
echo   Frontend Port: %FRONTEND_PORT%
echo.

echo [2/4] Starting Backend Server on port %BACKEND_PORT%...
echo.
start "Aegis Threat - Backend" cmd /k "cd backend && python -m uvicorn app.main:app --reload --port %BACKEND_PORT%"

REM Wait for backend to start
timeout /t 3 /nobreak >nul

echo [3/4] Starting Frontend Server on port %FRONTEND_PORT%...
echo.
start "Aegis Threat - Frontend" cmd /k "npm run dev -- --port %FRONTEND_PORT%"

REM Wait for frontend to start
timeout /t 3 /nobreak >nul

echo.
echo =====================================================
echo   Aegis Threat - Running!
echo =====================================================
echo.
echo Backend:  http://127.0.0.1:%BACKEND_PORT%
echo Frontend: http://localhost:%FRONTEND_PORT%
echo API Docs: http://127.0.0.1:%BACKEND_PORT%/docs
echo.
echo Features:
echo   - Hybrid NLP parsing (BlingFire + transformers + rules)
echo   - Semantic threat matching (sentence-transformers + FAISS)
echo   - Attack chain analysis (NetworkX)
echo   - STRIDE-based threat analysis
echo   - CWE, MITRE ATT^&CK, OWASP, NIST compliance mapping
echo   - Multi-LLM integration with RAG (OpenAI, Claude, Gemini)
echo   - PDF reports with architecture diagrams
echo.
echo Press any key to open the application in your browser...
pause >nul

REM Open the application in default browser
start http://localhost:%FRONTEND_PORT%

echo.
echo Application opened in browser.
echo.
echo To stop the servers, close the terminal windows.
echo.
echo Examples:
echo   start.bat
echo   start.bat --backend-port 3000
echo   start.bat -b 3000 -f 3001
echo.
