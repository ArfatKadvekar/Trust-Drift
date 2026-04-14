"""
main.py
=======
Standalone Pipeline Runner

Demonstrates the Trust-Drift pipeline with sample data.
Useful for testing and PoC demonstrations without FastAPI.

Usage:
    python main.py --file path/to/data.csv --entity-id 192.168.1.100
    python main.py --demo normal_traffic
    python main.py --demo sudden_attack
"""

import argparse
import json
import yaml
import sys
import numpy as np
from pathlib import Path
import io
import os

# Enable UTF-8 mode for Windows
os.environ['PYTHONIOENCODING'] = 'utf-8'

# Force UTF-8 output on all platforms
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
elif sys.platform == 'win32':
    # Fallback for older Python versions on Windows
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

from pipeline.input.loader import InputLayer
from pipeline.features.processor import FeatureProcessor
from pipeline.severity.scorer import SeverityLayer
from pipeline.explainability.explainer import ExplainabilityLayer
from pipeline.trust.engine import TrustLayer
from pipeline.enforcement.policy import EnforcementLayer
from pipeline.firewall.simulator import FirewallSimulator
from pipeline.utils.logger import JsonLogger


def load_config():
    """Load configuration from config.yaml."""
    config_path = Path("config.yaml")
    if not config_path.exists():
        return {}
    with open(config_path) as f:
        return yaml.safe_load(f) or {}


def run_pipeline_on_file(filepath: str, config: dict):
    """Run pipeline on a CSV file."""
    print(f"\n{'='*70}")
    print("TRUST-DRIFT PIPELINE - FILE MODE")
    print(f"{'='*70}\n")
    
    # Layer 1: Input
    print("[1/7] INPUT LAYER")
    input_layer = InputLayer()
    input_output = input_layer.load(filepath)
    print(f"  ✓ Loaded {input_output.rows:,} flows")
    
    # Layer 2: Features
    print("\n[2/7] FEATURE PROCESSING")
    feature_processor = FeatureProcessor(
        config.get("scaler_path", "./pipeline/severity/models/scaler.pkl")
    )
    df = input_layer.get_data()
    feature_cols = input_layer.get_feature_columns()
    features_output = feature_processor.process(df, feature_cols)
    print(f"  ✓ Scaled {len(features_output.X_scaled):,} rows × {features_output.n_features} features")
    
    # Layer 3: Severity
    print("\n[3/7] SEVERITY SCORING")
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
    
    # Calibrate on first 1000 benign samples
    n_calib = min(1000, len(features_output.X_scaled) // 2)
    severity_layer.calibrate(features_output.X_scaled[:n_calib])
    
    # Score all
    severity_scores = severity_layer.score_batch(features_output.X_scaled)
    mean_severity = np.mean([s.severity_score for s in severity_scores])
    max_severity = max([s.severity_score for s in severity_scores])
    print(f"  ✓ Scored {len(severity_scores)} flows")
    print(f"    Mean severity: {mean_severity:.4f}")
    print(f"    Max severity:  {max_severity:.4f}")
    
    # Layer 4: Explainability
    print("\n[4/7] EXPLAINABILITY")
    explainability_layer = ExplainabilityLayer()
    high_severity_flows = [
        (i, s) for i, s in enumerate(severity_scores)
        if s.severity_score > 0.5
    ]
    print(f"  ✓ Found {len(high_severity_flows)} high-severity flows")
    
    if high_severity_flows:
        idx, severity = high_severity_flows[0]
        expl = explainability_layer.explain(
            severity_score=severity.severity_score,
            top_features=severity.top_features,
            ae_score=severity.ae_score,
            if_score=severity.if_score,
        )
        print(f"\n  Most anomalous flow (index {idx}):")
        print(f"    Risk: {expl['risk_level']}")
        print(f"    Pattern: {expl['attack_pattern']}")
        print(f"    Top features: {', '.join(severity.top_features[:3])}")
        print(f"    Verdict: {expl['verdict'][:80]}...")
    
    # Layer 5-7: Trust, Enforcement, Firewall
    print("\n[5/7] TRUST ENGINE")
    trust_layer = TrustLayer(profile="Balanced")
    print(f"  ✓ Profile: Balanced")
    
    print("\n[6/7] ENFORCEMENT")
    enforcement_layer = EnforcementLayer()
    print(f"  ✓ Ready")
    
    print("\n[7/7] FIREWALL SIMULATION")
    firewall = FirewallSimulator()
    print(f"  ✓ Ready")
    
    # Simulate a few flows through full pipeline
    print("\n" + "="*70)
    print("SAMPLE FLOW ANALYSIS")
    print("="*70)
    
    for idx in [0, len(severity_scores)//2, -1]:
        severity = severity_scores[idx]
        trust = trust_layer.update(severity.severity_score)
        enforcement = enforcement_layer.enforce(
            trust.trust, trust.zone, f"flow_{idx}"
        )
        firewall_result = firewall.evaluate(
            entity_id=f"flow_{idx}",
            enforcement_action=enforcement.action,
            trust_score=trust.trust,
            severity_score=severity.severity_score,
            zone=trust.zone.value,
        )
        
        print(f"\nFlow #{idx}:")
        print(f"  Severity: {severity.severity_score:.4f} ({severity.explain_driver})")
        print(f"  Trust: {trust.trust:.4f} → Zone {trust.zone.value}")
        print(f"  Action: {firewall_result.firewall_action.value}")
        print(f"  Latency: {firewall_result.latency_ms:.1f}ms")
    
    print(f"\n\nFirewall Stats:")
    stats = firewall.get_stats()
    print(f"  Total entities: {stats['total_entities']}")
    print(f"  Allowed: {stats['allowed']} | Throttled: {stats['throttled']} | Blocked: {stats['blocked']} | Quarantined: {stats['quarantined']}")
    print()


def run_demo_mode(mode: str, config: dict):
    """Run pipeline in simulation mode with full transparency."""
    mode_names = {
        "normal_traffic": "NORMAL TRAFFIC",
        "sudden_attack": "ATTACK SCENARIO",
        "low_and_slow": "SLOW ATTACK"
    }
    
    print(f"\n{'=' * 86}")
    print(f"TRUST-DRIFT PIPELINE: {mode_names.get(mode, mode.upper())}")
    print(f"{'=' * 86}\n")
    
    # Initialize components
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
    
    # Calibrate with dummy data
    n_features = 41
    dummy_benign = np.random.normal(0.5, 0.1, (100, n_features)).astype(np.float32)
    dummy_benign = np.clip(dummy_benign, 0, 1)
    severity_layer.calibrate(dummy_benign)
    
    trust_layer = TrustLayer(profile="Balanced")
    explainability_layer = ExplainabilityLayer()
    enforcement_layer = EnforcementLayer()
    firewall = FirewallSimulator()
    
    # Generate synthetic flows
    n_flows = 50
    print(f"Generating {n_flows} synthetic flows in {mode} mode...\n")
    
    if mode == "normal_traffic":
        # Normal traffic: low severity
        severities = np.random.normal(0.15, 0.05, n_flows)
        severities = np.clip(severities, 0, 1)
    elif mode == "sudden_attack":
        # Attack spike in middle
        severities = np.concatenate([
            np.random.normal(0.1, 0.05, n_flows//2),  # Normal
            np.random.normal(0.85, 0.1, n_flows//2),  # Attack
        ])
        severities = np.clip(severities, 0, 1)
    elif mode == "low_and_slow":
        # Gradual increase
        severities = np.linspace(0.1, 0.7, n_flows)
    else:
        raise ValueError(f"Unknown mode: {mode}")
    
    # Process flows
    results = []
    trust_history = []
    
    # TABLE HEADER - Professional format
    print(f"{'Flow':<6} {'AE':<8} {'IF':<8} {'Severity':<10} {'Trust':<14} {'Zone':<6} {'Action':<10} {'Latency':<9}")
    print("-" * 86)
    
    for i, severity in enumerate(severities):
        # Add some noise
        severity = min(1.0, max(0.0, severity + np.random.normal(0, 0.02)))
        
        # Get severity scores (AE + IF breakdown)
        severity_output = severity_layer.score(np.array([severity] * n_features, dtype=np.float32))
        ae_score = severity_output.ae_score
        if_score = severity_output.if_score
        
        # Trust BEFORE
        trust_before = trust_layer.trust if hasattr(trust_layer, 'trust') else 1.0
        
        # Trust update
        trust = trust_layer.update(severity)
        trust_after = trust.trust
        
        # Enforcement
        enforcement = enforcement_layer.enforce(
            trust.trust, trust.zone.value, f"syn_{i}"
        )
        
        # Firewall
        fw = firewall.evaluate(
            entity_id=f"syn_{i}",
            enforcement_action=enforcement.action,
            trust_score=trust.trust,
            severity_score=severity,
            zone=trust.zone.value,
        )
        
        # GET EXPLAINABILITY OUTPUT (THE USP!)
        expl = explainability_layer.explain(
            severity_score=severity_output.severity_score,
            top_features=severity_output.top_features,
            ae_score=ae_score,
            if_score=if_score,
            trust_score=trust.trust,
        )
        
        results.append({
            "flow": i,
            "ae_score": ae_score,
            "if_score": if_score,
            "severity": severity,
            "trust_before": trust_before,
            "trust_after": trust_after,
            "zone": trust.zone.value,
            "fw_action": fw.firewall_action.value,
            "latency_ms": fw.latency_ms,
            "explainability": expl,
            "top_features": severity_output.top_features,
        })
        
        trust_history.append(trust_after)
        
        # TABLE ROW - Professional format with fixed decimals
        trust_display = f"{trust_before:.2f}->{trust_after:.2f}"
        print(f"{i:<6} {ae_score:<8.4f} {if_score:<8.4f} {severity:<10.4f} {trust_display:<14} {trust.zone.value:<6} {fw.firewall_action.value:<10} {fw.latency_ms:<9.1f}")
    
    # TRUST TIMELINE - Single clean line
    print("\n" + "=" * 86)
    print("TRUST TIMELINE")
    print("=" * 86)
    timeline_str = " -> ".join([f"{t:.2f}" for t in trust_history])
    print(f"[{timeline_str}]\n")
    
    # SUMMARY - Clean and minimal
    print("=" * 86)
    print("SUMMARY")
    print("=" * 86)
    stats = firewall.get_stats()
    
    print(f"\nTotal Flows: {n_flows}")
    print(f"Average Severity: {np.mean(severities):.4f}")
    print(f"Initial Trust Score: {trust_history[0]:.2f}")
    print(f"Final Trust Score: {trust_history[-1]:.2f}")
    print(f"\nFirewall Decisions:")
    print(f"  Allowed:    {stats['allowed']}")
    print(f"  Throttled:  {stats['throttled']}")
    print(f"  Blocked:    {stats['blocked']}")
    print(f"  Quarantined: {stats['quarantined']}")
    
    # SECURITY INSIGHTS - Professional format
    print("\n" + "=" * 86)
    print("SECURITY INSIGHTS")
    print("=" * 86)
    
    # Show formatted security reports for suspicious traffic  
    attack_flows = [(i, r) for i, r in enumerate(results) if r['severity'] > 0.6]
    
    # Save to UTF-8 file for proper formatting
    explainability_file = "security_report.txt"
    with open(explainability_file, 'w', encoding='utf-8') as f:
        f.write("\n" + "=" * 86 + "\n")
        f.write("SECURITY REPORT\n")
        f.write("=" * 86 + "\n\n")
        
        if attack_flows:
            for idx, (flow_idx, result) in enumerate(attack_flows[:3]):
                expl = result['explainability']
                f.write(f"Row {idx + 1} [Label: Detected Threat]\n\n")
                f.write(expl.get('formatted_box', "[ERROR: Unable to generate report]") + "\n\n")
        else:
            f.write("No significant threats detected during analysis period.\n")
    
    if attack_flows:
        print(f"\nDetected {len(attack_flows)} anomalous flows (Top 3 shown below):\n")
        
        for idx, (flow_idx, result) in enumerate(attack_flows[:3]):
            expl = result['explainability']
            print(f"Row {idx + 1} [Label: Detected Threat]\n")
            try:
                box = expl.get('formatted_box', "[ERROR: Unable to generate report]")
                print(box)
            except Exception:
                print(f"Trust Score   : {result['trust_after']:.2f} ({result['zone']})")
                print(f"Severity      : {result['severity']:.2f}")
                print(f"Attack Pattern: {expl.get('attack_pattern', 'Unknown')}")
                print(f"Risk Level: {expl.get('risk_level', 'Unknown')}")
            print()
    else:
        print("\nNo threats detected. All flows within normal parameters.")
    
    print(f"Report saved to: {explainability_file}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Trust-Drift Pipeline Standalone Runner"
    )
    parser.add_argument("--file", type=str, help="CSV file to analyze")
    parser.add_argument("--demo", type=str, 
                       choices=["normal_traffic", "sudden_attack", "low_and_slow"],
                       help="Run demo simulation")
    parser.add_argument("--entity-id", type=str, default=None,
                       help="Entity ID to filter on")
    
    args = parser.parse_args()
    
    config = load_config()
    
    if args.file:
        run_pipeline_on_file(args.file, config)
    elif args.demo:
        run_demo_mode(args.demo, config)
    else:
        print("Usage:")
        print("  File mode:   python main.py --file data.csv")
        print("  Demo mode:   python main.py --demo normal_traffic")
        parser.print_help()


if __name__ == "__main__":
    main()
