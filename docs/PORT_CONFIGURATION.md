# Port Configuration Guide

## Overview

The AI Threat Modeler allows you to customize the ports used by both the backend and frontend servers during startup.

## Default Ports

- **Backend**: 8000
- **Frontend**: 5173

## Configuration Methods

### 1. PowerShell Script (Recommended for Windows)

```powershell
# Default ports (8000, 5173)
.\start.ps1

# Custom backend port
.\start.ps1 -BackendPort 3000

# Custom frontend port
.\start.ps1 -FrontendPort 3001

# Both custom ports
.\start.ps1 -BackendPort 3000 -FrontendPort 3001
```

### 2. Batch Script

```bash
# Default ports
start.bat

# Custom backend port (long form)
start.bat --backend-port 3000

# Custom ports (short form)
start.bat -b 3000 -f 3001

# Show help
start.bat --help
```

### 3. Environment Variables

Create a `.env` file in the project root:

```bash
# Copy the example file
cp .env.example .env
```

Edit `.env` with your preferred ports:

```env
BACKEND_PORT=3000
FRONTEND_PORT=3001
VITE_API_URL=http://127.0.0.1:3000
```

### 4. Manual Start with Custom Ports

**Backend:**
```bash
cd backend
python -m uvicorn app.main:app --reload --port 3000
```

**Frontend:**
```bash
npm run dev -- --port 3001
```

## Examples

### Development Team Setup
```powershell
# Developer 1 - Default ports
.\start.ps1

# Developer 2 - Avoid conflicts
.\start.ps1 -BackendPort 8001 -FrontendPort 5174
```

### Production-like Testing
```powershell
# Use standard HTTP ports
.\start.ps1 -BackendPort 80 -FrontendPort 443
```

### Multiple Instances
```bash
# Instance 1
start.bat -b 8000 -f 5173

# Instance 2
start.bat -b 8001 -f 5174
```

## Troubleshooting

**Port Already in Use:**
- Check if another application is using the port
- Use `netstat -ano | findstr :PORT` to find the process
- Choose a different port or stop the conflicting application

**Frontend Can't Connect to Backend:**
- Ensure the `VITE_API_URL` in `.env` matches your backend port
- Check that both servers are running
- Verify firewall settings allow the connection
