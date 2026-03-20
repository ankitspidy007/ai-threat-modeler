"""
Streaming Analyzer — Wraps ThreatAnalyzer with progress callbacks
for real-time WebSocket updates.

Emits progress events at each analysis phase:
  parsing → rule_eval → semantic → severity → attack_chains → scoring → complete
"""

import asyncio
import logging
import json
from typing import Callable, Optional, Any
from datetime import datetime

from .parser import ArchitectureParser
from .mermaid_generator import generate_mermaid
from ..models import AnalysisResult, Threat, SystemArchitecture

logger = logging.getLogger(__name__)


PHASES = [
    {"id": "parsing", "label": "Parsing Architecture", "weight": 10},
    {"id": "rule_eval", "label": "Rule-Based Analysis", "weight": 20},
    {"id": "known_issues", "label": "Processing Known Issues", "weight": 5},
    {"id": "semantic", "label": "Semantic Threat Discovery", "weight": 20},
    {"id": "stride_classify", "label": "STRIDE Classification", "weight": 10},
    {"id": "severity", "label": "ML Severity Refinement", "weight": 10},
    {"id": "aggregation", "label": "Threat Aggregation", "weight": 5},
    {"id": "attack_chains", "label": "Attack Chain Analysis", "weight": 10},
    {"id": "scoring", "label": "Risk Scoring", "weight": 5},
    {"id": "reporting", "label": "Generating Report", "weight": 5},
]


class StreamingAnalyzer:
    """
    Streams analysis progress via async callbacks.
    
    Usage:
        analyzer = StreamingAnalyzer(progress_callback=my_callback)
        result = await analyzer.analyze_streaming(description, project_name)
    """
    
    def __init__(self, progress_callback: Callable = None, analyzer = None):
        self._callback = progress_callback
        self._analyzer = analyzer
        self._current_phase = 0
        self._total_weight = sum(p["weight"] for p in PHASES)
    
    async def _emit(self, phase_id: str, message: str, progress: float, 
                     partial_data: dict = None):
        """Emit a progress event."""
        event = {
            "type": "progress",
            "phase": phase_id,
            "message": message,
            "progress": round(progress, 1),
            "timestamp": datetime.now().isoformat(),
        }
        if partial_data:
            event["data"] = partial_data
        
        if self._callback:
            if asyncio.iscoroutinefunction(self._callback):
                await self._callback(event)
            else:
                self._callback(event)
        
        # Small yield to allow WebSocket to flush
        await asyncio.sleep(0.05)
    
    def _phase_progress(self, phase_index: int) -> float:
        """Calculate cumulative progress percentage at a given phase."""
        completed_weight = sum(PHASES[i]["weight"] for i in range(phase_index))
        return (completed_weight / self._total_weight) * 100
    
    async def analyze_streaming(self, description: str, 
                                 project_name: str = "Untitled Project",
                                 use_local_slm: bool = True,
                                 analysis_mode: str = "standard") -> AnalysisResult:
        """
        Run the full analysis pipeline with streaming progress updates.
        """
        from .analyzer import ThreatAnalyzer, STRIDE_MAPPING
        
        # We reuse ThreatAnalyzer's ML components but control the flow
        analyzer = self._analyzer or ThreatAnalyzer()
        analysis_flags = analyzer._analysis_flags(analysis_mode, use_local_slm)
        
        # ---- Phase 0: Parsing ----
        await self._emit("parsing", "Parsing architecture description...", 0)
        cache_key = analyzer._stable_hash({'description': description})
        architecture = analyzer._cache_get(analyzer._parsed_arch_cache, cache_key)
        if architecture is None:
            parser = ArchitectureParser()
            architecture = parser.parse(description)
            analyzer._cache_set(analyzer._parsed_arch_cache, cache_key, architecture, max_size=32)
        
        component_count = len(architecture.components)
        flow_count = len(architecture.flows)
        await self._emit("parsing", 
                         f"Found {component_count} components, {flow_count} data flows",
                         self._phase_progress(1),
                         {"components": component_count, "flows": flow_count})
        
        # ---- Phase 1: Rule-based Analysis ----
        await self._emit("rule_eval", "Running rule-based threat evaluation...",
                         self._phase_progress(1))
        
        graph = analyzer._get_cached_graph(architecture)
        raw_threats = []
        prioritized_nodes = analyzer._prioritize_component_nodes(graph)
        prioritized_edges = analyzer._prioritize_flow_edges(graph)
        
        # Evaluate components
        for node_id, data in prioritized_nodes:
            threats = analyzer.rule_engine.evaluate_component(node_id, data)
            raw_threats.extend(threats)
        
        # Evaluate flows
        for u, v, data in prioritized_edges:
            threats = analyzer.rule_engine.evaluate_flow(u, v, data)
            raw_threats.extend(threats)
        
        await self._emit("rule_eval",
                         f"Rule engine found {len(raw_threats)} potential threats",
                         self._phase_progress(2),
                         {"rule_threats": len(raw_threats)})
        
        # ---- Phase 2: Known Issues ----
        await self._emit("known_issues", "Processing known issues...",
                         self._phase_progress(2))
        known_threats = analyzer._process_known_issues(architecture)
        raw_threats.extend(known_threats)
        
        await self._emit("known_issues",
                         f"Processed {len(known_threats)} known issues",
                         self._phase_progress(3))
        
        # ---- Phase 3: Semantic Discovery ----
        semantic_count = 0
        if analyzer._semantic_matcher and analysis_flags["semantic_matching"]:
            await self._emit("semantic", 
                             "Running semantic threat matching (FAISS vector search)...",
                             self._phase_progress(3))
            semantic_threats = analyzer._discover_semantic_threats(
                architecture,
                graph,
                top_k=analysis_flags["semantic_top_k"]
            )
            semantic_count = len(semantic_threats)
            raw_threats.extend(semantic_threats)
            await self._emit("semantic",
                             f"Semantic search discovered {semantic_count} additional threats",
                             self._phase_progress(4),
                             {"semantic_threats": semantic_count})
        else:
            await self._emit("semantic", "Semantic matching not enabled or not available (skipped)",
                             self._phase_progress(4))
        
        # ---- Phase 4: STRIDE Classification ----
        if analyzer._stride_classifier and analyzer._stride_classifier.is_trained:
            await self._emit("stride_classify",
                             f"Classifying threats with trained STRIDE model "
                             f"(accuracy: {analyzer._stride_classifier.accuracy:.0%})...",
                             self._phase_progress(4))
        else:
            await self._emit("stride_classify", 
                             "Using zero-shot STRIDE classification...",
                             self._phase_progress(4))
        
        await self._emit("stride_classify", "STRIDE classification complete",
                         self._phase_progress(5))
        
        # ---- Phase 5: Aggregation ----
        await self._emit("aggregation", "Aggregating threats by ID...",
                         self._phase_progress(6))
        aggregated = analyzer._aggregate_threats_by_id(raw_threats)
        
        # ---- Phase 6: ML Severity ----
        if analyzer._severity_classifier and analysis_flags["severity_refinement"]:
            await self._emit("severity",
                             f"ML severity refinement on {len(aggregated)} threats...",
                             self._phase_progress(5))
            aggregated = analyzer._refine_severity(aggregated, architecture)
            await self._emit("severity", "Severity refinement complete",
                             self._phase_progress(6))
        else:
            await self._emit("severity", "ML severity not available (skipped)",
                             self._phase_progress(6))
        
        # ---- Phase 7: Confidence gating + classification ----
        gated = analyzer._apply_confidence_gating(aggregated)
        classified = analyzer._classify_tiers(gated)
        normalized = analyzer._normalize_stride(classified)
        
        # ---- Phase 8: Attack Chains ----
        attack_chain_summary = None
        if analyzer._attack_chain_analyzer and analysis_flags["attack_chains"]:
            await self._emit("attack_chains", "Building attack chain graph...",
                             self._phase_progress(7))
            try:
                attack_chain_summary = analyzer._get_attack_chain_summary()
                chains_found = attack_chain_summary.get('chains', 0)
                await self._emit("attack_chains",
                                f"Found {chains_found} attack chains",
                                self._phase_progress(8),
                                {"chains": chains_found})
            except Exception as e:
                await self._emit("attack_chains", f"Attack chain analysis failed: {e}",
                                self._phase_progress(8))
        else:
            await self._emit("attack_chains", "Attack chains not available (skipped)",
                             self._phase_progress(8))
        
        # ---- Phase 9: Scoring ----
        await self._emit("scoring", "Calculating risk score...",
                         self._phase_progress(8))
        score = analyzer._calculate_score(normalized)
        
        # ---- Phase 10: Report ----
        await self._emit("reporting", "Generating diagram and report...",
                         self._phase_progress(9))
        
        diagram = generate_mermaid(graph, threats=normalized, enhanced=True)
        
        confirmed = [t for t in normalized if t.tier == "Confirmed"]
        potential = [t for t in normalized if t.tier == "Potential"]
        
        result = AnalysisResult(
            project_name=project_name,
            summary=f"Analysis complete. {len(confirmed)} confirmed risks, {len(potential)} potential risks.",
            threats=normalized,
            architecture=architecture,
            score=score,
            mermaid_diagram=diagram,
            diagram=diagram,
            timestamp=datetime.now().isoformat()
        )
        
        if attack_chain_summary:
            result.attack_chains = attack_chain_summary
        
        result.ml_enhanced = {
            'semantic_matching': analyzer._semantic_matcher is not None and analysis_flags["semantic_matching"],
            'stride_classifier': analyzer._stride_classifier is not None and analyzer._stride_classifier.is_trained,
            'severity_classifier': analyzer._severity_classifier is not None and analysis_flags["severity_refinement"],
            'attack_chains': analyzer._attack_chain_analyzer is not None and analysis_flags["attack_chains"],
            'analysis_mode': analysis_flags["mode"],
            'nlp_parser': architecture.metadata.get('nlp_enhanced', False),
        }
        result.coverage = analyzer._build_coverage(architecture, normalized, analysis_flags)
        
        result.report_markdown = analyzer._generate_report_markdown(result)
        
        # ---- Complete ----
        await self._emit("complete", 
                         f"Analysis complete: {len(normalized)} threats, score: {score}/100",
                         100,
                         {"total_threats": len(normalized), "score": score,
                          "confirmed": len(confirmed), "potential": len(potential)})
        
        return result
