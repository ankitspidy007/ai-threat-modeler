import os
import json
import time
import hashlib
from contextlib import asynccontextmanager
from collections import OrderedDict
from typing import Dict, Optional, Tuple
from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator

from .engine.analyzer import ThreatAnalyzer
from .models import AnalysisResult
from .services.llm_analyzer import LLMAnalyzer

# Environment-based configuration
ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:5173,http://localhost:3000").split(",")
ADMIN_API_TOKEN = os.getenv("ADMIN_API_TOKEN", "")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Warm expensive analyzer dependencies once at startup."""
    app.state.threat_analyzer = ThreatAnalyzer()
    yield


app = FastAPI(
    title="Aegis Threat API", 
    version="0.2.0",
    description="Aegis Threat API for AI-assisted threat modeling and architecture risk analysis",
    lifespan=lifespan
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
    use_local_slm: bool = Field(default=True, description="Enable local semantic analysis")
    analysis_mode: str = Field(default="standard", description="Analysis mode: fast, standard, or deep")
    domain_profile: str = Field(default="general", description="Optional domain profile: general, saas, fintech, healthcare, ai, platform")
    
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

    @field_validator('analysis_mode')
    @classmethod
    def validate_analysis_mode(cls, v):
        if v not in ['fast', 'standard', 'deep']:
            return 'standard'
        return v

    @field_validator('domain_profile')
    @classmethod
    def validate_domain_profile(cls, v):
        if v not in ['general', 'saas', 'fintech', 'healthcare', 'ai', 'platform']:
            return 'general'
        return v


class IaCAnalyzeRequest(BaseModel):
    project_name: str = Field(..., min_length=1, max_length=200, description="Name of the project")
    iac_content: str = Field(..., min_length=10, description="Raw Content of Docker Compose or Kubernetes YAML")
    format_hint: str = Field(default='auto', description="Hint for parser: 'auto', 'docker-compose', 'kubernetes'")
    analysis_mode: str = Field(default="standard", description="Analysis mode: fast, standard, or deep")
    
    @field_validator('project_name')
    @classmethod
    def sanitize_project_name(cls, v):
        import re
        sanitized = re.sub(r'[<>"\'\\/;]', '', v)
        return sanitized.strip()

    @field_validator('format_hint')
    @classmethod
    def validate_format_hint(cls, v):
        if v not in ['auto', 'docker-compose', 'kubernetes']:
            return 'auto'
        return v

    @field_validator('analysis_mode')
    @classmethod
    def validate_analysis_mode(cls, v):
        if v not in ['fast', 'standard', 'deep']:
            return 'standard'
        return v


class LLMAnalyzeRequest(BaseModel):
    project_name: str = Field(..., min_length=1, max_length=200)
    description: str = Field(..., min_length=10, max_length=10000)
    llm_provider: str = Field(..., description="LLM provider: 'openai' or 'claude'")
    api_key: str = Field(..., min_length=10, description="API key for the LLM provider")
    model: Optional[str] = Field(default=None, description="Optional specific model to use")
    analysis_mode: str = Field(default="standard", description="Analysis mode: fast, standard, or deep")
    
    @field_validator('llm_provider')
    @classmethod
    def validate_provider(cls, v):
        if v.lower() not in ['openai', 'claude', 'gemini']:
            raise ValueError('Provider must be "openai", "claude", or "gemini"')
        return v.lower()

    @field_validator('analysis_mode')
    @classmethod
    def validate_analysis_mode(cls, v):
        if v not in ['fast', 'standard', 'deep']:
            return 'standard'
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


class RetrainLocalModelsResponse(BaseModel):
    message: str
    stats: dict


class TTLAnalysisCache:
    def __init__(self, max_entries: int = 100, ttl_seconds: int = 900):
        self.max_entries = max_entries
        self.ttl_seconds = ttl_seconds
        self._store: "OrderedDict[str, Tuple[float, AnalysisResult]]" = OrderedDict()

    def _purge_expired(self):
        now = time.time()
        expired = [key for key, (expires_at, _) in self._store.items() if expires_at <= now]
        for key in expired:
            self._store.pop(key, None)

    def get(self, key: str):
        self._purge_expired()
        item = self._store.get(key)
        if item is None:
            return None
        expires_at, value = item
        if expires_at <= time.time():
            self._store.pop(key, None)
            return None
        self._store.move_to_end(key)
        return value

    def set(self, key: str, value: AnalysisResult):
        self._purge_expired()
        self._store[key] = (time.time() + self.ttl_seconds, value)
        self._store.move_to_end(key)
        while len(self._store) > self.max_entries:
            self._store.popitem(last=False)

    def clear(self) -> int:
        count = len(self._store)
        self._store.clear()
        return count


_analysis_cache = TTLAnalysisCache()
_latest_analysis_by_project: Dict[str, AnalysisResult] = {}


def _stable_cache_key(*parts) -> str:
    payload = json.dumps(parts, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _build_diff_summary(previous: Optional[AnalysisResult], current: AnalysisResult) -> Optional[dict]:
    if previous is None:
        return None
    previous_threats = {threat.id: threat for threat in previous.threats}
    current_threats = {threat.id: threat for threat in current.threats}
    previous_ids = set(previous_threats)
    current_ids = set(current_threats)
    new_ids = sorted(current_ids - previous_ids)
    resolved_ids = sorted(previous_ids - current_ids)
    score_delta = current.score - previous.score
    component_delta = len(current.architecture.components) - len(previous.architecture.components)
    flow_delta = len(current.architecture.flows) - len(previous.architecture.flows)

    severity_changes = []
    for threat_id in sorted(previous_ids & current_ids):
        previous_threat = previous_threats[threat_id]
        current_threat = current_threats[threat_id]
        if previous_threat.severity != current_threat.severity or previous_threat.tier != current_threat.tier:
            severity_changes.append({
                "id": threat_id,
                "title": current_threat.title,
                "from_severity": previous_threat.severity,
                "to_severity": current_threat.severity,
                "from_tier": previous_threat.tier,
                "to_tier": current_threat.tier,
            })

    if not new_ids and not resolved_ids and not severity_changes and score_delta == 0 and component_delta == 0 and flow_delta == 0:
        return {
            "compared_to_project": previous.project_name,
            "new_threats": [],
            "resolved_threats": [],
            "severity_changes": [],
            "score_delta": 0,
            "component_delta": 0,
            "flow_delta": 0,
            "changed": False,
        }
    return {
        "compared_to_project": previous.project_name,
        "new_threats": [
            {
                "id": threat_id,
                "title": current_threats[threat_id].title,
                "severity": current_threats[threat_id].severity,
                "tier": current_threats[threat_id].tier,
            }
            for threat_id in new_ids
        ],
        "resolved_threats": [
            {
                "id": threat_id,
                "title": previous_threats[threat_id].title,
                "severity": previous_threats[threat_id].severity,
                "tier": previous_threats[threat_id].tier,
            }
            for threat_id in resolved_ids
        ],
        "severity_changes": severity_changes,
        "score_delta": score_delta,
        "component_delta": component_delta,
        "flow_delta": flow_delta,
        "changed": True,
    }


def _require_admin(request: Request):
    if ENVIRONMENT != "production" and not ADMIN_API_TOKEN:
        return
    provided = request.headers.get("x-admin-token")
    if not ADMIN_API_TOKEN or provided != ADMIN_API_TOKEN:
        raise HTTPException(status_code=403, detail="Admin token required")


def get_shared_analyzer(request_or_socket) -> ThreatAnalyzer:
    """Return the warmed shared analyzer, or fall back to constructing one."""
    analyzer = getattr(request_or_socket.app.state, "threat_analyzer", None)
    return analyzer or ThreatAnalyzer()


@app.post("/analyze", response_model=AnalysisResult)
async def analyze(request: Request, payload: AnalyzeRequest):
    """
    Analyze a system architecture description for potential security threats.
    
    - Uses STRIDE methodology for threat categorization
    - Returns threats with confidence levels and remediation advice
    """
    try:
        # Cache key includes the effective analysis settings.
        cache_key = _stable_cache_key(
            payload.description,
            payload.project_name,
            payload.use_local_slm,
            payload.analysis_mode,
            payload.domain_profile
        )
        
        cached = _analysis_cache.get(cache_key)
        if cached is not None:
            return cached
        
        analyzer = get_shared_analyzer(request)
        previous_result = _latest_analysis_by_project.get(payload.project_name)
        result = analyzer.analyze_from_text(
            payload.description,
            payload.project_name,
            use_local_slm=payload.use_local_slm,
            analysis_mode=payload.analysis_mode,
            domain_profile=payload.domain_profile
        )
        result.diff_summary = _build_diff_summary(previous_result, result)
        
        _analysis_cache.set(cache_key, result)
        _latest_analysis_by_project[payload.project_name] = result
        
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@app.post("/analyze-iac", response_model=AnalysisResult)
async def analyze_iac(request: Request, payload: IaCAnalyzeRequest):
    """
    Analyze Infrastructure-as-Code (Docker Compose or Kubernetes).
    """
    try:
        from .engine.iac_parser import IaCParser
        
        # 1. Parse IaC into SystemArchitecture
        parser = IaCParser()
        system_architecture = parser.parse(payload.iac_content, payload.format_hint)
        
        if not system_architecture.components:
            raise ValueError("No valid components or services found in the provided IaC file.")
            
        # 2. Run analysis
        analyzer = get_shared_analyzer(request)
        previous_result = _latest_analysis_by_project.get(payload.project_name)
        result = analyzer.analyze(
            system_architecture,
            payload.project_name,
            analysis_mode=payload.analysis_mode
        )
        result.diff_summary = _build_diff_summary(previous_result, result)
        _latest_analysis_by_project[payload.project_name] = result
        
        return result
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"IaC Analysis failed: {str(e)}")


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
async def clear_cache(request: Request):
    """Clear the analysis cache (admin endpoint)."""
    _require_admin(request)
    count = _analysis_cache.clear()
    _latest_analysis_by_project.clear()
    return {"message": f"Cleared {count} cached entries"}


@app.post("/admin/retrain-local-models", response_model=RetrainLocalModelsResponse)
async def retrain_local_models(request: Request):
    """Reload KB data and rebuild local semantic/classifier artifacts."""
    try:
        _require_admin(request)
        analyzer = get_shared_analyzer(request)
        stats = analyzer.reload_local_intelligence()
        return {
            "message": "Local knowledge base and models rebuilt successfully",
            "stats": stats,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Local retraining failed: {str(e)}")


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
        use_local_slm = payload.get('use_local_slm', True)
        analysis_mode = payload.get('analysis_mode', 'standard')
        domain_profile = payload.get('domain_profile', 'general')
        
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
        
        shared_analyzer = get_shared_analyzer(websocket)
        streaming_analyzer = StreamingAnalyzer(
            progress_callback=send_progress,
            analyzer=shared_analyzer
        )
        result = await streaming_analyzer.analyze_streaming(
            description,
            project_name,
            use_local_slm=use_local_slm,
            analysis_mode=analysis_mode,
            domain_profile=domain_profile
        )
        
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
        analyzer = get_shared_analyzer(request)
        previous_result = _latest_analysis_by_project.get(payload.project_name)
        rule_based_result = analyzer.analyze_from_text(
            payload.description,
            payload.project_name,
            analysis_mode=payload.analysis_mode
        )
        
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
        rule_based_result.diff_summary = _build_diff_summary(previous_result, rule_based_result)
        _latest_analysis_by_project[payload.project_name] = rule_based_result
        
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
