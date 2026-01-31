from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .engine.analyzer import ThreatAnalyzer
from .models import AnalysisResult

app = FastAPI(title="AI Threat Modeler API", version="0.1.0")

# Enable CORS for the frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class AnalyzeRequest(BaseModel):
    project_name: str
    description: str

@app.post("/analyze", response_model=AnalysisResult)
async def analyze(request: AnalyzeRequest):
    try:
        analyzer = ThreatAnalyzer()
        result = analyzer.analyze_from_text(request.description, request.project_name)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
def health_check():
    return {"status": "ok"}
