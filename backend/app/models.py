from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

class Component(BaseModel):
    id: str
    name: str
    type: str  # API, Database, Service, WebClient, etc.
    description: Optional[str] = ""
    properties: Dict[str, Any] = Field(default_factory=dict)
    # Common properties: auth_type, logging_enabled, encryption_at_rest, rate_limiting, input_validation

class DataFlow(BaseModel):
    source_id: str
    target_id: str
    protocol: str  # http, https, tcp, etc.
    properties: Dict[str, Any] = Field(default_factory=dict)

class SystemArchitecture(BaseModel):
    components: List[Component]
    flows: List[DataFlow]
    metadata: Optional[Dict[str, Any]] = {}  # NEW: For known issues and other metadata

class Threat(BaseModel):
    id: str
    category: str
    stride_category: Optional[str] = None  # Normalized STRIDE mapping
    title: str
    description: str
    severity: str
    likelihood: Optional[str] = "Unknown"
    impact: Optional[str] = "Unknown"
    risk_score: Optional[int] = 0
    confidence: Optional[str] = "Medium"  # High, Medium, Low
    tier: Optional[str] = "Potential"  # Confirmed, Potential
    status: Optional[str] = "Identified"
    evidence: List[str] = Field(default_factory=list)
    mitigation: str
    # Compliance & framework mappings
    owasp_top_10: Optional[List[str]] = Field(default_factory=list)
    cwe: Optional[List[str]] = Field(default_factory=list)
    mitre_attack: Optional[List[str]] = Field(default_factory=list)
    nist_800_53: Optional[List[str]] = Field(default_factory=list)
    # Aggregated fields
    affected_components: List[str] = Field(default_factory=list)
    affected_data_flows: List[str] = Field(default_factory=list)
    # Legacy fields (kept for compatibility)
    component_id: Optional[str] = None
    flow_source: Optional[str] = None
    flow_target: Optional[str] = None

class AnalysisResult(BaseModel):
    project_name: str
    summary: str
    threats: List[Threat]
    architecture: SystemArchitecture
    score: int
    mermaid_diagram: Optional[str] = None
    diagram: Optional[str] = None  # Alias for frontend compatibility
    report_markdown: Optional[str] = None
    timestamp: Optional[str] = None  # For tracking when analysis was done
    # NLP/DL enhancement fields
    attack_chains: Optional[Dict[str, Any]] = None  # Attack chain analysis summary
    ml_enhanced: Optional[Dict[str, Any]] = None  # Which ML features were active
    architecture_insights: Optional[List[Dict[str, Any]]] = None  # Architecture intelligence insights

