import os
import json
from typing import Optional
from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator

from .engine.analyzer import ThreatAnalyzer
from .models import AnalysisResult
from .services.llm_analyzer import LLMAnalyzer

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
    
    @field_validator('project_name')
    @classmethod
    def sanitize_project_name(cls, v):
        # Remove potentially dangerous characters
        import re
        sanitized = re.sub(r'[<>"\'\\/;]', '', v)
        return sanitized.strip()
    
    @field_validator('description')
    @classmethod
    def validate_description(cls, v):
        if not v or len(v.strip()) < 10:
            raise ValueError('Description must be at least 10 characters')
        return v.strip()


class LLMAnalyzeRequest(BaseModel):
    project_name: str = Field(..., min_length=1, max_length=200)
    description: str = Field(..., min_length=10, max_length=10000)
    llm_provider: str = Field(..., description="LLM provider: 'openai' or 'claude'")
    api_key: str = Field(..., min_length=10, description="API key for the LLM provider")
    model: Optional[str] = Field(default=None, description="Optional specific model to use")
    
    @field_validator('llm_provider')
    @classmethod
    def validate_provider(cls, v):
        if v.lower() not in ['openai', 'claude', 'gemini']:
            raise ValueError('Provider must be "openai", "claude", or "gemini"')
        return v.lower()


class APIKeyValidationRequest(BaseModel):
    provider: str = Field(..., description="LLM provider: 'openai' or 'claude'")
    api_key: str = Field(..., min_length=10)
    
    @field_validator('provider')
    @classmethod
    def validate_provider(cls, v):
        if v.lower() not in ['openai', 'claude', 'gemini']:
            raise ValueError('Provider must be "openai", "claude", or "gemini"')
        return v.lower()


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
    # Report NLP/DL capabilities
    ml_features = {
        'nlp_parser': False,
        'semantic_matching': False,
        'attack_chains': False,
    }
    try:
        from .engine.nlp_processor import SPACY_AVAILABLE
        ml_features['nlp_parser'] = SPACY_AVAILABLE
    except ImportError:
        pass
    try:
        from .engine.embedding_service import EMBEDDINGS_AVAILABLE, FAISS_AVAILABLE
        ml_features['semantic_matching'] = EMBEDDINGS_AVAILABLE
        ml_features['vector_search'] = FAISS_AVAILABLE
    except ImportError:
        pass
    try:
        from .engine.attack_chain import NX_AVAILABLE
        ml_features['attack_chains'] = NX_AVAILABLE
    except ImportError:
        pass
    
    return {
        "status": "ok",
        "version": "2.0.0",
        "environment": ENVIRONMENT,
        "ml_features": ml_features
    }


@app.delete("/cache")
async def clear_cache():
    """Clear the analysis cache (admin endpoint)."""
    global _analysis_cache
    count = len(_analysis_cache)
    _analysis_cache = {}
    return {"message": f"Cleared {count} cached entries"}


@app.websocket("/ws/analyze")
async def websocket_analyze(websocket: WebSocket):
    """
    WebSocket endpoint for streaming analysis progress.
    
    Client sends: {"description": "...", "project_name": "..."}
    Server streams: {"type": "progress", "phase": "...", "progress": 0-100, "message": "..."}
    Final message:  {"type": "result", "data": <full analysis result>}
    """
    await websocket.accept()
    
    try:
        # Receive analysis request
        data = await websocket.receive_text()
        payload = json.loads(data)
        
        description = payload.get('description', '')
        project_name = payload.get('project_name', 'Untitled Project')
        
        if not description or len(description) < 10:
            await websocket.send_json({
                "type": "error",
                "message": "Description must be at least 10 characters"
            })
            await websocket.close()
            return
        
        # Create streaming analyzer with WebSocket callback
        from .engine.streaming_analyzer import StreamingAnalyzer
        
        async def send_progress(event):
            try:
                await websocket.send_json(event)
            except Exception:
                pass  # Client may have disconnected
        
        streaming_analyzer = StreamingAnalyzer(progress_callback=send_progress)
        result = await streaming_analyzer.analyze_streaming(description, project_name)
        
        # Send final result
        result_dict = result.model_dump() if hasattr(result, 'model_dump') else result.dict()
        await websocket.send_json({
            "type": "result",
            "data": result_dict
        })
        
    except WebSocketDisconnect:
        pass  # Client disconnected
    except json.JSONDecodeError:
        await websocket.send_json({
            "type": "error",
            "message": "Invalid JSON payload"
        })
    except Exception as e:
        try:
            await websocket.send_json({
                "type": "error",
                "message": f"Analysis failed: {str(e)}"
            })
        except Exception:
            pass
    finally:
        try:
            await websocket.close()
        except Exception:
            pass


@app.post("/analyze-with-llm", response_model=AnalysisResult)
async def analyze_with_llm(request: Request, payload: LLMAnalyzeRequest):
    """
    Analyze architecture with LLM enhancement (OpenAI, Claude, or Gemini).
    
    - Runs both rule-based and LLM analysis
    - Uses RAG: retrieves relevant KB threats to include in LLM prompt
    - Semantic deduplication when merging threats
    - LLM threats marked with [AI] prefix
    """
    try:
        # Run rule-based analysis (includes NLP + semantic matching)
        analyzer = ThreatAnalyzer()
        rule_based_result = analyzer.analyze_from_text(payload.description, payload.project_name)
        
        # RAG: Retrieve relevant KB threats for LLM context
        kb_context = None
        try:
            from .engine.semantic_matcher import get_semantic_matcher
            matcher = get_semantic_matcher()
            results = matcher.find_threats_for_architecture(payload.description, top_k=10)
            kb_context = [
                {
                    'threat_name': meta.get('threat_name', ''),
                    'category': meta.get('category', ''),
                    'severity': meta.get('severity', ''),
                    'score': score
                }
                for meta, score in results
                if score > 0.4
            ]
        except Exception:
            pass  # RAG is optional
        
        # Run LLM analysis with RAG context
        llm_threats = LLMAnalyzer.analyze_with_llm(
            architecture_description=payload.description,
            project_name=payload.project_name,
            provider=payload.llm_provider,
            api_key=payload.api_key,
            model=payload.model,
            kb_context=kb_context
        )
        
        # Merge threats with semantic deduplication
        merged_threats = LLMAnalyzer.merge_threats(rule_based_result.threats, llm_threats)
        
        # Update result with merged threats
        rule_based_result.threats = merged_threats
        rule_based_result.summary = (
            f"Analysis complete with {payload.llm_provider.upper()} enhancement. "
            f"{len(merged_threats)} threats identified "
            f"(RAG context: {len(kb_context) if kb_context else 0} KB threats)."
        )
        
        return rule_based_result
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"LLM analysis failed: {str(e)}")


@app.post("/validate-api-key")
async def validate_api_key(payload: APIKeyValidationRequest):
    """
    Validate an LLM API key.
    
    Returns:
        {"valid": true/false, "provider": "openai"/"claude"}
    """
    try:
        is_valid = LLMAnalyzer.validate_api_key(payload.provider, payload.api_key)
        return {
            "valid": is_valid,
            "provider": payload.provider
        }
    except Exception as e:
        return {
            "valid": False,
            "provider": payload.provider,
            "error": str(e)
        }
