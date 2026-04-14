"""
pipeline/api/server.py
======================
FastAPI server: REST API for Trust-Drift pipeline.

Endpoints:
  POST   /analyze           - Run full pipeline on single flow
  GET    /trust-history     - Get trust history for entity
  GET    /firewall-logs     - Get firewall decision logs
  GET    /alerts            - Get high-severity incidents
  GET    /stats             - Get system statistics
  GET    /health            - Health check
"""

from __future__ import annotations

import json
import uuid
from typing import Optional
from datetime import datetime

from fastapi import FastAPI, Query, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from pipeline.input.loader import InputLayer
from pipeline.features.processor import FeatureProcessor
from pipeline.severity.scorer import SeverityLayer
from pipeline.explainability.explainer import ExplainabilityLayer
from pipeline.trust.engine import TrustLayer
from pipeline.enforcement.policy import EnforcementLayer
from pipeline.firewall.simulator import FirewallSimulator

from pipeline.utils.models import (
    PipelineRequest,
    PipelineResponse,
    PipelineSummary,
    Zone,
    RiskLevel as RiskLevelEnum,
    get_timestamp,
)
from pipeline.utils.logger import JsonLogger


def create_app(
    config: Optional[dict] = None,
    debug: bool = False,
) -> FastAPI:
    """
    Create FastAPI application with full Trust-Drift pipeline.
    
    Parameters
    ----------
    config : dict, optional
        Configuration overrides
    debug : bool
        Enable debug mode (full trace logging)
    
    Returns
    -------
    FastAPI
        Configured application instance
    """
    
    app = FastAPI(
        title="Trust-Drift Pipeline",
        description="Production-grade Zero Trust network pipeline",
        version="1.0.0",
    )
    
    # Initialize components
    print("[API] Initializing pipeline components...")
    
    # Logger
    logger = JsonLogger(log_dir="./logs", debug=debug)
    
    # Load configuration defaults
    if config is None:
        config = {}

    # API config and CORS for dashboard/frontend integration
    api_config = config.get("api", {})
    cors_config = api_config.get("cors", {})
    allowed_origins = cors_config.get("allowed_origins", ["*"])
    allow_credentials = cors_config.get("allow_credentials", False)
    allow_methods = cors_config.get("allow_methods", ["*"])
    allow_headers = cors_config.get("allow_headers", ["*"])

    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=allow_credentials,
        allow_methods=allow_methods,
        allow_headers=allow_headers,
    )
    
    # Initialize pipeline layers
    severity_config = config.get("severity", {})
    severity_layer = SeverityLayer(
        autoencoder_path=severity_config.get("autoencoder_path", 
            "./pipeline/severity/models/autoencoder.keras"),
        encoder_path=severity_config.get("encoder_path", 
            "./pipeline/severity/models/encoder.keras"),
        iso_forest_path=severity_config.get("iso_forest_path", 
            "./pipeline/severity/models/iso_forest.pkl"),
        scaler_path=severity_config.get("scaler_path", 
            "./pipeline/severity/models/scaler.pkl"),
        feature_cols_path=severity_config.get("feature_cols_path", 
            "./pipeline/severity/models/feature_cols.pkl"),
        allow_fallback=severity_config.get("allow_fallback", True),
    )
    print("[API] ✓ Severity layer initialized")
    
    trust_profile = config.get("trust_profile") or config.get("trust", {}).get("profile", "Balanced")
    trust_layer = TrustLayer(profile=trust_profile)
    print("[API] ✓ Trust layer loaded")
    
    explainability_layer = ExplainabilityLayer()
    print("[API] ✓ Explainability layer loaded")
    
    enforcement_layer = EnforcementLayer()
    print("[API] ✓ Enforcement layer loaded")
    
    firewall_config = config.get("firewall", {})
    firewall_simulator = FirewallSimulator(
        enable_latency_simulation=config.get("firewall_latency", firewall_config.get("enabled", True)),
        throttle_latency_min_ms=config.get("throttle_min_ms", firewall_config.get("throttle_latency_min_ms", 50)),
        throttle_latency_max_ms=config.get("throttle_max_ms", firewall_config.get("throttle_latency_max_ms", 200)),
    )
    print("[API] ✓ Firewall simulator loaded")
    
    # ──────────────────────────────────────────────────────────────────────────
    # Routes
    # ──────────────────────────────────────────────────────────────────────────
    
    @app.get("/health")
    async def health_check():
        """Health check endpoint."""
        return {
            "status": "healthy",
            "timestamp": get_timestamp(),
            "pipeline_ready": severity_layer is not None,
        }
    
    @app.post("/analyze")
    async def analyze(request: dict):
        """
        Analyze a single network flow through the full pipeline.
        
        Request JSON:
        {
            "entity_id": "192.168.1.100",
            "feature_vector": [0.1, 0.2, ..., 0.9],  # 41 features
            "debug": false
        }
        
        Returns: Full pipeline response with all layer outputs
        """
        request_id = f"req_{uuid.uuid4().hex[:8]}"
        request_dict = request
        debug = request_dict.get("debug", False)
        
        try:
            # Validate input
            entity_id = request_dict.get("entity_id", "unknown")
            feature_vector = request_dict.get("feature_vector")
            
            if not feature_vector or len(feature_vector) != 41:
                raise ValueError("feature_vector must have exactly 41 elements")
            
            import numpy as np
            X_scaled = np.array([feature_vector], dtype=np.float32)
            
            # Check severity layer is ready
            if severity_layer is None:
                raise RuntimeError("Severity layer not initialized")
            
            # ── SEVERITY LAYER ──────────────────────────────────────────────
            severity_output = severity_layer.score(X_scaled[0])
            logger.log_severity(request_id, {
                "entity_id": entity_id,
                "severity": severity_output.__dict__,
            })
            
            # ── EXPLAINABILITY LAYER ────────────────────────────────────────
            explainability_output = explainability_layer.explain(
                severity_score=severity_output.severity_score,
                top_features=severity_output.top_features,
                ae_score=severity_output.ae_score,
                if_score=severity_output.if_score,
                trust_score=0.5,  # placeholder, will use actual trust before this
            )
            logger.log_explainability(request_id, {
                "entity_id": entity_id,
                "explanation": explainability_output,
            })
            
            # ── TRUST ENGINE ────────────────────────────────────────────────
            trust_output = trust_layer.update(severity_output.severity_score)
            logger.log_trust(request_id, {
                "entity_id": entity_id,
                "trust": trust_output.__dict__,
            })
            
            # ── ENFORCEMENT LAYER ───────────────────────────────────────────
            enforcement_output = enforcement_layer.enforce(
                trust=trust_output.trust,
                zone=trust_output.zone,
                entity_id=entity_id,
            )
            logger.log_enforcement(request_id, {
                "entity_id": entity_id,
                "enforcement": enforcement_output.__dict__,
            })
            
            # ── FIREWALL SIMULATION ─────────────────────────────────────────
            firewall_output = firewall_simulator.evaluate(
                entity_id=entity_id,
                enforcement_action=enforcement_output.action,
                trust_score=trust_output.trust,
                severity_score=severity_output.severity_score,
                zone=trust_output.zone.value,
            )
            logger.log_firewall(request_id, {
                "entity_id": entity_id,
                "firewall": firewall_output.__dict__,
            })
            
            # ── SUMMARY ─────────────────────────────────────────────────────
            summary = PipelineSummary(
                severity=severity_output.severity_score,
                trust=trust_output.trust,
                zone=trust_output.zone,
                action=enforcement_output.action,
                risk_level=RiskLevelEnum[explainability_output["risk_level"]],
                allow=firewall_output.request_allowed,
            )
            
            # Build TRANSPARENT response for dashboard
            response = {
                "request_id": request_id,
                "timestamp": get_timestamp(),
                "status": "success",
                "entity_id": entity_id,
                
                # LAYER 1: INPUT (preserved for completeness)
                "input": {
                    "feature_vector_length": len(feature_vector),
                    "features_received": len([f for f in feature_vector if f is not None]),
                },
                
                # LAYER 2: FEATURES (scaling info)
                "features": {
                    "n_features": 41,
                    "range": [0.0, 1.0],
                    "normalized": True,
                },
                
                # LAYER 3: SEVERITY (FULL TRANSPARENCY - AE vs IF breakdown)
                "severity": {
                    "ae_score": float(round(severity_output.ae_score, 4)),
                    "if_score": float(round(severity_output.if_score, 4)),
                    "combined": float(round(severity_output.severity_score, 4)),
                    "weights": {
                        "ae_weight": round(severity_output.weight_ae, 4),
                        "if_weight": round(severity_output.weight_if, 4),
                    },
                    "top_anomalous_features": severity_output.top_features,
                    "scoring_method": severity_output.explain_driver,  # "real" or "SIM"
                },
                
                # LAYER 4: EXPLAINABILITY
                "explainability": {
                    "risk_level": explainability_output.get("risk_level"),
                    "attack_pattern": explainability_output.get("attack_pattern"),
                    "explanation": explainability_output.get("explanation"),
                    "verdict": explainability_output.get("verdict"),
                    "zone_description": explainability_output.get("zone_info"),
                    "system_action": explainability_output.get("system_action"),
                },
                
                # LAYER 5: TRUST (BEFORE & AFTER)
                "trust": {
                    "before": float(round(1.0, 4)),  # Get from entity state if available
                    "after": float(round(trust_output.trust, 4)),
                    "zone": trust_output.zone.value,
                    "decay_applied": trust_output.decayed,
                    "decay_reason": f"severity={severity_output.severity_score:.4f}" if trust_output.decayed else "None",
                },
                
                # LAYER 6: ENFORCEMENT
                "enforcement": {
                    "action": enforcement_output.action,
                    "zone": enforcement_output.zone.value,
                    "mfa_required": enforcement_output.mfa_required,
                    "rate_limit_rps": enforcement_output.rate_limit_rps,
                    "quarantined": enforcement_output.quarantine,
                },
                
                # LAYER 7: FIREWALL
                "firewall": {
                    "action": firewall_output.firewall_action.value,
                    "status": firewall_output.status.value,
                    "latency_ms": float(round(firewall_output.latency_ms, 2)),
                    "reason": firewall_output.reason,
                    "request_allowed": firewall_output.request_allowed,
                },
                
                # SUMMARY (for quick dashboard view)
                "summary": {
                    "severity_score": float(round(severity_output.severity_score, 4)),
                    "trust_score": float(round(trust_output.trust, 4)),
                    "zone": trust_output.zone.value,
                    "risk_level": explainability_output.get("risk_level"),
                    "final_action": firewall_output.firewall_action.value,
                    "allow": firewall_output.request_allowed,
                    "urgent": severity_output.severity_score > 0.8,
                },
                
                # TIMELINE READY (for graphing)
                "timeline": {
                    "entity_id": entity_id,
                    "timestamp": get_timestamp(),
                    "severity_trend": float(round(severity_output.severity_score, 4)),
                    "trust_trend": float(round(trust_output.trust, 4)),
                    "zone_history": trust_output.zone.value,
                },
                
                "debug_trace": None,
            }
            
            if debug:
                response["debug_trace"] = {
                    "request_id": request_id,
                    "entity_id": entity_id,
                    "layers_executed": list(response.keys()),
                    "severity_breakdown": {
                        "ae": severity_output.ae_score,
                        "if": severity_output.if_score,
                        "combined": severity_output.severity_score,
                    },
                }
            
            return response
        
        except Exception as e:
            logger.log_error = f"{str(e)}"
            return {
                "request_id": request_id,
                "status": "error",
                "error": str(e),
                "timestamp": get_timestamp(),
            }
    
    @app.get("/stats")
    async def get_stats():
        """Get firewall statistics."""
        return {
            "timestamp": get_timestamp(),
            "firewall": firewall_simulator.get_stats(),
            "total_decisions": len(firewall_simulator.get_decisions()),
        }
    
    @app.get("/firewall-logs")
    async def get_firewall_logs(
        action: Optional[str] = Query(None),
        limit: int = Query(100, ge=1, le=1000),
    ):
        """Get firewall decision logs."""
        logs = firewall_simulator.get_decisions(limit=limit)
        if action:
            logs = [log for log in logs if log.get("action") == action]
        return {
            "timestamp": get_timestamp(),
            "count": len(logs),
            "logs": logs[-limit:],
        }
    
    @app.get("/alerts")
    async def get_alerts(
        min_severity: float = Query(0.7, ge=0, le=1),
        limit: int = Query(50, ge=1, le=1000),
    ):
        """Get high-severity incidents."""
        decisions = firewall_simulator.get_decisions(limit=1000)
        alerts = [
            d for d in decisions
            if d.get("severity_score", 0) >= min_severity
        ]
        return {
            "timestamp": get_timestamp(),
            "count": len(alerts),
            "min_severity": min_severity,
            "alerts": alerts[-limit:],
        }
    
    @app.get("/entities")
    async def get_entities():
        """Get all tracked entities and their states."""
        entities = [e.to_dict() for e in firewall_simulator.get_all_entities()]
        return {
            "timestamp": get_timestamp(),
            "count": len(entities),
            "entities": entities,
        }
    
    print("[API] ✓ All routes initialized")
    
    return app


# Module-level app instance for ease of import
app = create_app()
