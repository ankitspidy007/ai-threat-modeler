import os
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, validator

from .engine.analyzer import ThreatAnalyzer
from .models import AnalysisResult

# Environment-based configuration
ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:5173,http://localhost:3000").split(",")

app = FastAPI(
    title="AI Threat Modeler API", 
    version="0.2.0",
    description="AI-powered threat modeling API using STRIDE methodology"
)

# Environment-based CORS configuration
if ENVIRONMENT == "production":
    app.add_middleware(
        CORSMiddleware,
        allow_origins=ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type", "Authorization"],
    )
else:
    # Development mode - allow all origins
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )


class AnalyzeRequest(BaseModel):
    project_name: str = Field(..., min_length=1, max_length=200, description="Name of the project")
    description: str = Field(..., min_length=10, max_length=10000, description="System architecture description")
    
    @validator('project_name')
    def sanitize_project_name(cls, v):
        # Remove potentially dangerous characters
        import re
        sanitized = re.sub(r'[<>"\'\\/;]', '', v)
        return sanitized.strip()
    
    @validator('description')
    def validate_description(cls, v):
        if not v or len(v.strip()) < 10:
            raise ValueError('Description must be at least 10 characters')
        return v.strip()


# In-memory cache for analysis results
_analysis_cache = {}


@app.post("/analyze", response_model=AnalysisResult)
async def analyze(request: Request, payload: AnalyzeRequest):
    """
    Analyze a system architecture description for potential security threats.
    
    - Uses STRIDE methodology for threat categorization
    - Returns threats with confidence levels and remediation advice
    """
    try:
        # Simple cache key based on description hash
        cache_key = hash(payload.description + payload.project_name)
        
        if cache_key in _analysis_cache:
            return _analysis_cache[cache_key]
        
        analyzer = ThreatAnalyzer()
        result = analyzer.analyze_from_text(payload.description, payload.project_name)
        
        # Cache the result (limit cache size to 100 entries)
        if len(_analysis_cache) < 100:
            _analysis_cache[cache_key] = result
        
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@app.get("/health")
def health_check():
    """Health check endpoint for monitoring."""
    return {"status": "ok", "version": "0.2.0", "environment": ENVIRONMENT}


@app.delete("/cache")
async def clear_cache():
    """Clear the analysis cache (admin endpoint)."""
    global _analysis_cache
    count = len(_analysis_cache)
    _analysis_cache = {}
    return {"message": f"Cleared {count} cached entries"}
