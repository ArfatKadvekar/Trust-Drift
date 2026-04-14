"""
pipeline/explainability/explainer.py
=====================================
Explainability Layer: Converts severity scores and anomalous features into human-readable explanations.

Uses the EXACT functions from explain.py without any modification.
No rewrites, no reimplementation - direct wrapper.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Import the EXACT functions from explain.py
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from Test_Model.test_model.explain import (
    get_risk_level,
    generate_explanation,
    generate_verdict,
    infer_attack,
    get_zone_info,
    generate_mitre_playbook,
)

from pipeline.utils.models import get_timestamp


class ExplainabilityLayer:
    """
    Explainability Layer: Maps severity + features → human-readable explanation.
    
    Uses the EXACT functions from explain.py.
    No ML, fast execution, fully interpretable.
    """
    
    def __init__(self):
        print("[ExplainabilityLayer] Initialized")
    
    def explain(
        self,
        severity_score: float,
        top_features: list[str],
        ae_score: float,
        if_score: float,
        trust_score: float = 1.0,
    ) -> dict:
        """
        Generate explanation for an anomalous flow.
        
        Uses the EXACT format from explain.py functions.
        
        Parameters
        ----------
        severity_score : float ∈ [0, 1]
            Combined severity score from Severity Layer
        top_features : list[str]
            Top N anomalous feature names
        ae_score : float
            Autoencoder severity score
        if_score : float
            Isolation Forest severity score
        trust_score : float
            Trust value for zone determination
        
        Returns
        -------
        dict
            Explanation output with EXACT format from explain.py functions
            Includes "formatted_box" for direct display
        """
        
        # Use the EXACT functions from explain.py
        risk_level = get_risk_level(severity_score)
        attack_pattern = infer_attack(top_features)
        explanation_text = generate_explanation(severity_score, top_features)
        verdict = generate_verdict(risk_level, top_features)
        zone_str, system_action = get_zone_info(trust_score)
        
        # Build diagnostics dict for MITRE playbook generation
        diag = {
            "severity_score": severity_score,
            "top_features": top_features,
            "ae_score": ae_score,
            "if_score": if_score,
            "feature_errors": [severity_score] * len(top_features),  # Use severity as proxy for errors
        }
        
        # Generate formatted MITRE playbook box (for display)
        formatted_box = generate_mitre_playbook(trust_score, diag)
        
        # Return in the EXACT format from explain.py
        return {
            "risk_level": risk_level,
            "severity_score": severity_score,
            "attack_pattern": attack_pattern,
            "explanation": explanation_text,
            "verdict": verdict,
            "zone_info": zone_str,
            "system_action": system_action,
            "top_features": top_features,
            "ae_score": round(ae_score, 6),
            "if_score": round(if_score, 6),
            "dominant_sensor": "AE" if ae_score >= if_score else "IF",
            "timestamp": get_timestamp(),
            "formatted_box": formatted_box,  # NEW: Formatted MITRE playbook for direct display
        }
