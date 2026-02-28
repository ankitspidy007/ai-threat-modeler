# AITM - AI Threat Modeler v2.0 - Startup Script
# Usage: .\start.ps1 [-BackendPort 8000] [-FrontendPort 5173]

param(
    [int]$BackendPort = 8000,
    [int]$FrontendPort = 5173
)

Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host "  AITM - AI Threat Modeler v2.0" -ForegroundColor Cyan
Write-Host "  STRIDE Analysis | Multi-LLM | Compliance Mapping" -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host ""

# Check if Python is installed
try {
    $pythonVersion = python --version 2>&1
    Write-Host "[✓] Python found: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "[✗] ERROR: Python is not installed or not in PATH" -ForegroundColor Red
    Write-Host "    Please install Python 3.8 or higher" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

# Check if Node.js is installed
try {
    $nodeVersion = node --version 2>&1
    Write-Host "[✓] Node.js found: $nodeVersion" -ForegroundColor Green
} catch {
    Write-Host "[✗] ERROR: Node.js is not installed or not in PATH" -ForegroundColor Red
    Write-Host "    Please install Node.js 18 or higher" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host ""
Write-Host "[1/4] Checking dependencies..." -ForegroundColor Yellow

# Check if frontend dependencies are installed
if (-not (Test-Path "node_modules")) {
    Write-Host "    Installing frontend dependencies..." -ForegroundColor Yellow
    npm install
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[✗] Failed to install frontend dependencies" -ForegroundColor Red
        Read-Host "Press Enter to exit"
        exit 1
    }
}

# Check if backend dependencies are installed (check for uvicorn)
$uvicornInstalled = pip show uvicorn 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "    Installing backend dependencies..." -ForegroundColor Yellow
    Set-Location backend
    pip install -r requirements.txt
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[✗] Failed to install backend dependencies" -ForegroundColor Red
        Set-Location ..
        Read-Host "Press Enter to exit"
        exit 1
    }
    Set-Location ..
}

Write-Host "[✓] Dependencies ready" -ForegroundColor Green
Write-Host ""

# Display port configuration
Write-Host "Port Configuration:" -ForegroundColor Cyan
Write-Host "  Backend Port:  $BackendPort" -ForegroundColor White
Write-Host "  Frontend Port: $FrontendPort" -ForegroundColor White
Write-Host ""

# Start Backend Server
Write-Host "[2/4] Starting Backend Server on port $BackendPort..." -ForegroundColor Yellow
$backendJob = Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PWD\backend'; python -m uvicorn app.main:app --reload --port $BackendPort" -PassThru -WindowStyle Normal
Start-Sleep -Seconds 3

# Start Frontend Server with custom port
Write-Host "[3/4] Starting Frontend Server on port $FrontendPort..." -ForegroundColor Yellow
$env:VITE_PORT = $FrontendPort
$env:VITE_BACKEND_URL = "http://127.0.0.1:$BackendPort"
$frontendJob = Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PWD'; `$env:PORT=$FrontendPort; npm run dev -- --port $FrontendPort" -PassThru -WindowStyle Normal
Start-Sleep -Seconds 3

Write-Host ""
Write-Host "=====================================================" -ForegroundColor Green
Write-Host "  AITM - AI Threat Modeler - Running!" -ForegroundColor Green
Write-Host "=====================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Backend:  " -NoNewline
Write-Host "http://127.0.0.1:$BackendPort" -ForegroundColor Cyan
Write-Host "Frontend: " -NoNewline
Write-Host "http://localhost:$FrontendPort" -ForegroundColor Cyan
Write-Host "API Docs: " -NoNewline
Write-Host "http://127.0.0.1:$BackendPort/docs" -ForegroundColor Cyan
Write-Host ""
Write-Host "Features:" -ForegroundColor Cyan
Write-Host "  - STRIDE-based threat analysis" -ForegroundColor Gray
Write-Host "  - CWE, MITRE ATT&CK, OWASP, NIST compliance mapping" -ForegroundColor Gray
Write-Host "  - Multi-LLM integration (OpenAI, Claude, Gemini)" -ForegroundColor Gray
Write-Host "  - PDF reports with architecture diagrams" -ForegroundColor Gray
Write-Host ""
Write-Host "Opening application in browser..." -ForegroundColor Yellow
Start-Sleep -Seconds 2

# Open the application in default browser
Start-Process "http://localhost:$FrontendPort"

Write-Host ""
Write-Host "[✓] Application opened in browser" -ForegroundColor Green
Write-Host ""
Write-Host "To stop the servers, close the PowerShell windows." -ForegroundColor Yellow
Write-Host ""
Write-Host "Examples:" -ForegroundColor Cyan
Write-Host "  .\start.ps1                          # Use default ports (8000, 5173)" -ForegroundColor Gray
Write-Host "  .\start.ps1 -BackendPort 3000        # Backend on 3000, Frontend on 5173" -ForegroundColor Gray
Write-Host "  .\start.ps1 -FrontendPort 3001       # Backend on 8000, Frontend on 3001" -ForegroundColor Gray
Write-Host "  .\start.ps1 -BackendPort 3000 -FrontendPort 3001  # Custom ports" -ForegroundColor Gray
Write-Host ""
