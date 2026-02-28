# =============================================================================
# AITM - AI Threat Modeler v2.0
# Multi-stage Dockerfile: Build frontend → Serve with FastAPI backend
# =============================================================================

# ---------------------
# Stage 1: Build Frontend
# ---------------------
FROM node:20-alpine AS frontend-build

WORKDIR /app

# Copy package files first for better layer caching
COPY package.json package-lock.json* ./

# Install frontend dependencies
RUN npm ci --production=false

# Copy frontend source
COPY index.html vite.config.js tailwind.config.js postcss.config.js ./
COPY src/ ./src/
COPY public/ ./public/ 2>/dev/null || true

# Build frontend — API calls go to same origin in production
ENV VITE_API_URL=""
RUN npm run build

# ---------------------
# Stage 2: Python Backend + Serve Static
# ---------------------
FROM python:3.11-slim AS production

WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies
COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt && \
    python -m spacy download en_core_web_sm 2>/dev/null || true

# Copy backend source
COPY backend/app/ ./app/

# Copy built frontend from Stage 1
COPY --from=frontend-build /app/dist ./static/

# Create a startup script that serves both frontend and backend
RUN cat > /app/serve.py << 'EOF'
"""
Production server: FastAPI backend + static frontend files.
"""
import os
from pathlib import Path
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from app.main import app

# Serve static frontend files
static_dir = Path("/app/static")
if static_dir.exists():
    # Serve assets (JS, CSS, images)
    app.mount("/assets", StaticFiles(directory=str(static_dir / "assets")), name="assets")
    
    # Catch-all: serve index.html for any non-API route (SPA routing)
    @app.get("/{path:path}")
    async def serve_spa(path: str):
        file_path = static_dir / path
        if file_path.exists() and file_path.is_file():
            return FileResponse(str(file_path))
        return FileResponse(str(static_dir / "index.html"))
EOF

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run with uvicorn
CMD ["python", "-m", "uvicorn", "serve:app", "--host", "0.0.0.0", "--port", "8000"]
