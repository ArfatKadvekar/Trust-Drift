# Trust-Drift POC Complete Guide

**Version:** 1.0.0
**Scope:** End-to-end documentation of the current Trust-Drift proof of concept
**Status:** Implemented architecture plus notes on documented-but-not-fully-wired settings

This guide explains the full pipeline from input to firewall action, the formulas used in scoring and trust evolution, the runtime entry points, the fallback behavior, and the main configuration knobs.

## 1. What This POC Does

Trust-Drift is a Zero Trust style behavioral security pipeline. It takes a network flow, normalizes the features, assigns an anomaly severity score using a hybrid Autoencoder + Isolation Forest model, translates that severity into a trust update, maps trust to an enforcement zone, and simulates the resulting firewall action with per-entity state tracking.

The codebase is organized around 8 layers:

1. Input loading
2. Feature processing
3. Severity scoring
4. Explainability
5. Trust evolution
6. Enforcement policy
7. Firewall simulation
8. API surface

Core files:

- [README.md](README.md)
- [main.py](main.py)
- [run.py](run.py)
- [app.py](app.py)
- [config.yaml](config.yaml)
- [severity_scorer.py](severity_scorer.py)
- [trust_engine.py](trust_engine.py)
- [pipeline/input/loader.py](pipeline/input/loader.py)
- [pipeline/features/processor.py](pipeline/features/processor.py)
- [pipeline/severity/scorer.py](pipeline/severity/scorer.py)
- [pipeline/severity/model_loader.py](pipeline/severity/model_loader.py)
- [pipeline/explainability/explainer.py](pipeline/explainability/explainer.py)
- [pipeline/trust/engine.py](pipeline/trust/engine.py)
- [pipeline/enforcement/policy.py](pipeline/enforcement/policy.py)
- [pipeline/firewall/simulator.py](pipeline/firewall/simulator.py)
- [pipeline/firewall/state.py](pipeline/firewall/state.py)
- [pipeline/api/server.py](pipeline/api/server.py)
- [pipeline/utils/models.py](pipeline/utils/models.py)
- [Test_Model/test_model/explain.py](Test_Model/test_model/explain.py)

## 2. End-to-End Flow

The typical flow is:

1. Load a CSV flow or receive a request payload.
2. Separate metadata columns from feature columns.
3. Scale features with a fitted MinMaxScaler.
4. Score the flow with AE + IF severity logic.
5. Generate a human-readable explanation.
6. Update trust using decay or recovery.
7. Map trust to an enforcement zone and action.
8. Simulate firewall handling with state and latency.
9. Return the result through CLI or API.

The most direct pipeline wiring is in [pipeline/api/server.py](pipeline/api/server.py) and [main.py](main.py).

## 3. Entry Points

### CLI runner

The main CLI is [run.py](run.py). It supports:

- `demo` to run sample traffic scenarios
- `api` to start the FastAPI server
- `train` to generate models from synthetic data
- `all` to run training, demo, and API startup

### Standalone pipeline demo

[main.py](main.py) runs the pipeline without FastAPI. It has two modes:

- File mode: process a CSV
- Demo mode: generate synthetic severity streams for `normal_traffic`, `sudden_attack`, and `low_and_slow`

### FastAPI app

[app.py](app.py) loads `config.yaml`, creates the app from [pipeline/api/server.py](pipeline/api/server.py), and starts Uvicorn when executed directly.

## 4. Layer-by-Layer Architecture

### Layer 1: Input

File: [pipeline/input/loader.py](pipeline/input/loader.py)

Role:

- Load CSV data
- Reject missing or empty files
- Preserve metadata columns
- Expose feature-only data for later stages

Behavior:

- Reads a CSV into a DataFrame
- Stores metadata like shape, dtypes, null counts, and file name
- Treats `Flow ID`, `Source IP`, `Destination IP`, and `Label` as metadata columns
- Returns feature columns by excluding those metadata columns

### Layer 2: Feature Processing

File: [pipeline/features/processor.py](pipeline/features/processor.py)

Role:

- Load a fitted scaler
- Validate the feature count
- Scale raw values into the model input space

The processor uses the fitted scaler's `transform()` method. In the intended model path, this is a MinMaxScaler.

### Layer 3: Severity Sensor

Files:

- [pipeline/severity/scorer.py](pipeline/severity/scorer.py)
- [severity_scorer.py](severity_scorer.py)
- [pipeline/severity/model_loader.py](pipeline/severity/model_loader.py)

Role:

- Compute anomaly severity from two signals
- Normalize and combine those signals
- Return top anomalous features and diagnostics
- Fall back to deterministic simulation when model artifacts are missing

### Layer 4: Explainability

Files:

- [pipeline/explainability/explainer.py](pipeline/explainability/explainer.py)
- [Test_Model/test_model/explain.py](Test_Model/test_model/explain.py)

Role:

- Convert numeric outputs into readable risk statements
- Infer likely attack patterns from top features
- Produce verdict text and MITRE-style playbook output

### Layer 5: Trust Engine

Files:

- [pipeline/trust/engine.py](pipeline/trust/engine.py)
- [trust_engine.py](trust_engine.py)

Role:

- Maintain a per-entity trust score
- Apply exponential decay when severity is high
- Apply linear recovery when severity is low
- Map trust to a zone

### Layer 6: Enforcement

File: [pipeline/enforcement/policy.py](pipeline/enforcement/policy.py)

Role:

- Convert trust zone into an action
- Attach MFA, throttle, or quarantine behavior
- Return structured enforcement output

### Layer 7: Firewall Simulation

Files:

- [pipeline/firewall/simulator.py](pipeline/firewall/simulator.py)
- [pipeline/firewall/state.py](pipeline/firewall/state.py)

Role:

- Apply firewall behavior based on the enforcement action
- Track per-entity state
- Record actions and counters
- Simulate realistic latency for throttled requests

### Layer 8: API

File: [pipeline/api/server.py](pipeline/api/server.py)

Role:

- Expose the full pipeline via HTTP
- Provide health, analysis, stats, alerts, logs, and trust-history endpoints

## 5. Core Formulas

This section documents the implemented formulas, not just the high-level intent.

### 5.1 Feature scaling

The feature processor uses MinMax scaling:

$$
X_{scaled} = \frac{X - X_{min}}{X_{max} - X_{min}}
$$

This is the preprocessing step before severity scoring.

### 5.2 Autoencoder reconstruction error

The severity scorer computes the per-row reconstruction error as mean squared error:

$$
AE_{raw} = \operatorname{mean}((X - \hat{X})^2, axis=1)
$$

Where:

- $X$ is the scaled input row
- $\hat{X}$ is the autoencoder reconstruction

Feature-level anomaly attribution uses absolute reconstruction error:

$$
feature\_error_j = |x_j - \hat{x}_j|
$$

### 5.3 Isolation Forest raw score

The Isolation Forest score is converted so that larger values mean more anomalous behavior:

$$
IF_{raw} = -\text{score\_samples}(X)
$$

### 5.4 Percentile normalization

Both AE and IF raw scores are normalized with percentile anchors fitted on benign-only calibration data:

$$
norm(x) = \operatorname{clip}\left(\frac{x - p_{low}}{p_{high} - p_{low}}, 0, 1\right)
$$

Default anchors in the scorer are the 1st and 99th percentiles.

This avoids the flattening effect of min-max scaling when a few extreme values are present.

### 5.5 Dynamic per-row weighting

The implemented weighting is dynamic and per-row, not a fixed constant alpha.

Let:

$$
ae = AE_{sev}, \quad if = IF_{sev}, \quad \epsilon = 10^{-9}
$$

Then:

$$
w_{ae} = \frac{ae}{ae + if + \epsilon}
$$

$$
w_{if} = 1 - w_{ae}
$$

Final severity:

$$
Severity = w_{ae} \cdot ae + w_{if} \cdot if
$$

Interpretation:

- If AE dominates, the AE weight increases.
- If IF dominates, the IF weight increases.
- If both are low, the combined severity stays low.
- If both are high, both contribute, but the stronger sensor gets more weight.

### 5.6 EMA smoothing

Batch scoring optionally smooths the combined severity with an exponential moving average:

$$
s_t = \alpha r_t + (1 - \alpha) s_{t-1}
$$

Where:

- $r_t$ is the raw combined severity
- $s_t$ is the smoothed severity
- $\alpha$ is `ema_alpha`

This is applied in `score_dataset()` and helps prevent one noisy sample from spiking downstream trust.

### 5.7 Trust decay

The trust engine applies exponential decay when severity crosses the anomaly threshold:

$$
T(t + \Delta t) = T(t) \times e^{-\lambda \times s}
$$

Where:

- $T(t)$ is current trust
- $s$ is severity
- $\lambda$ is the decay constant

### 5.8 Trust recovery

When severity is below the threshold, trust recovers linearly:

$$
T(t + \Delta t) = \min(1, T(t) + \mu \times \Delta t)
$$

Where:

- $\mu$ is the recovery rate
- $\Delta t$ is elapsed time since the previous update

### 5.9 Trust zone thresholds

Trust is mapped into three zones:

- Zone A: $T > 0.8$
- Zone B: $0.4 < T \le 0.8$
- Zone C: $T \le 0.4$

The trust engine exposes this through `classify_zone()` in [trust_engine.py](trust_engine.py).

### 5.10 Enforcement mapping

The enforcement layer maps zones to actions:

- Zone A: full access, no MFA, no quarantine
- Zone B: step-up MFA + session throttling, rate limit 10 RPS
- Zone C: quarantine / session terminated, rate limit 0

### 5.11 Firewall latency

The firewall simulator assigns different latencies by action:

- Allow: 1 ms
- Throttle: random delay between configured minimum and maximum, typically 50 to 200 ms
- Block: 0 ms

## 6. Implemented Logic by Module

### 6.1 Severity scoring in the core scorer

File: [severity_scorer.py](severity_scorer.py)

Implemented behavior:

- Calibrate on benign data
- Predict reconstructions with the autoencoder
- Compute AE MSE per row
- Score Isolation Forest samples
- Normalize both scores using percentile anchors
- Compute dynamic weights per row
- Produce top features by absolute reconstruction error
- Optionally smooth batch output with EMA

The scorer returns:

- `severity_score`
- `ae_score`
- `if_score`
- `weights`
- `top_features`
- `feature_errors`

### 6.2 Fallback severity simulator

File: [pipeline/severity/model_loader.py](pipeline/severity/model_loader.py)

If model files are missing and fallback is enabled, the system uses a deterministic simulator.

Scenarios:

- `normal`: low base severity with small noise
- `attack`: high base severity with larger noise
- `gradual`: severity driven by variance and max value
- default: anomaly score driven by variance and max value

The fallback mode is meant for demo reliability, not for final security analysis.

### 6.3 Trust evolution

File: [trust_engine.py](trust_engine.py)

Implemented behavior:

- Clamp lambda and mu to safe bounds
- Decay trust if severity is above the threshold
- Recover trust otherwise
- Recompute zone and action on every update

The pipeline wrapper in [pipeline/trust/engine.py](pipeline/trust/engine.py) defines three profiles:

- High: `lambda_=3.0`, `mu=0.01`
- Balanced: `lambda_=1.5`, `mu=0.05`
- Low: `lambda_=0.5`, `mu=0.10`

All profiles use an anomaly threshold of `0.5`.

### 6.4 Explainability

File: [Test_Model/test_model/explain.py](Test_Model/test_model/explain.py)

Implemented thresholds:

- Severity < 0.2: LOW
- Severity < 0.5: MEDIUM
- Severity < 0.8: HIGH
- Otherwise: CRITICAL

Attack inference priority:

1. SYN Flag patterns
2. Bulk patterns
3. PSH patterns
4. URG patterns
5. Unknown anomaly pattern

The MITRE-style playbook uses the top features, severity, AE score, IF score, and trust score to generate a structured incident summary.

### 6.5 Firewall state tracking

File: [pipeline/firewall/state.py](pipeline/firewall/state.py)

Each entity tracks:

- Current status
- Current trust
- Allowed, throttled, blocked, and quarantined counts
- Quarantine reason and timestamps
- Last action and history
- Throttle limit

Action history is capped at the last 100 actions.

### 6.6 Firewall evaluation

File: [pipeline/firewall/simulator.py](pipeline/firewall/simulator.py)

Mapping logic:

- Full access -> ALLOW
- Step-up MFA + throttling -> THROTTLE
- Quarantine -> BLOCK
- Unknown action -> BLOCK as a precaution

The simulator also updates entity state, logs decisions, and returns a `FirewallOutput` object.

## 7. API Surface

File: [pipeline/api/server.py](pipeline/api/server.py)

Endpoints:

- `POST /analyze` - analyze a single flow
- `GET /health` - health check
- `GET /stats` - summary statistics
- `GET /alerts` - high severity events
- `GET /firewall-logs` - firewall audit trail
- `GET /trust-history` - entity trust timeline
- `GET /entities` - tracked entities

The API composes the full pipeline in this order:

1. Severity
2. Explainability
3. Trust
4. Enforcement
5. Firewall

## 8. Configuration Guide

File: [config.yaml](config.yaml)

### 8.1 Severity settings

- `allow_fallback`: enable simulation if models are missing
- `fallback_seed`: keep simulation deterministic
- `percentile_low` and `percentile_high`: documented calibration bounds
- `ema_alpha`: smoothing factor
- `top_n_features`: number of anomalous features to return

### 8.2 Trust profiles

- `High`: fast decay, slow recovery
- `Balanced`: default middle ground
- `Low`: slow decay, fast recovery

### 8.3 Enforcement zones

- Zone A: allow
- Zone B: throttle + MFA
- Zone C: block / quarantine

### 8.4 Firewall settings

- `throttle_latency_min_ms`
- `throttle_latency_max_ms`
- `quarantine_expiry_minutes`

## 9. Real Models vs Fallback Mode

The POC supports two operating modes:

### Real model mode

Activated when these artifacts exist:

- `autoencoder.keras`
- `encoder.keras`
- `iso_forest.pkl`
- `scaler.pkl`
- `feature_cols.pkl`

### Fallback mode

If the model files are missing and `allow_fallback` is `true`, the system switches to deterministic simulation and keeps the pipeline running.

This is handled by [pipeline/severity/model_loader.py](pipeline/severity/model_loader.py).

## 10. Data Contracts

Shared dataclasses and enums are defined in [pipeline/utils/models.py](pipeline/utils/models.py).

Important objects:

- `SeverityOutput`
- `TrustOutput`
- `EnforcementOutput`
- `FirewallOutput`
- `PipelineSummary`
- `RiskLevel`
- `Zone`
- `FirewallAction`
- `RequestStatus`

These contracts keep the pipeline layers loosely coupled and explicit.

## 11. Important Implementation Notes

1. The implemented severity combiner uses dynamic per-row weighting, not a fixed alpha blend.
2. The core scorer normalizes with percentile anchors after calibration, not plain min-max over the final scores.
3. The fallback severity path is deterministic and intentionally simple so demos keep working even without trained artifacts.
4. The trust profiles are hardcoded in [pipeline/trust/engine.py](pipeline/trust/engine.py).
5. The firewall simulator keeps per-entity action history and counters, which makes it suitable for audits and demos.

## 12. Current Wiring Notes

The codebase includes a few documented settings that are not wired identically across every entry point.

- [config.yaml](config.yaml) nests settings under sections like `trust:` and `firewall:`, while [pipeline/api/server.py](pipeline/api/server.py) reads some flattened keys such as `trust_profile`, `firewall_latency`, `throttle_min_ms`, and `throttle_max_ms`.
- The severity scorer supports percentile anchors and EMA smoothing, but the main runtime paths mostly rely on the scorer defaults unless the wrapper passes overrides.
- The fallback simulator path is fully wired and is the safest way to keep the demo running when model artifacts are absent.

## 13. Recommended Runtime Paths

For a quick demo:

```bash
python main.py --demo normal_traffic
python main.py --demo sudden_attack
python main.py --demo low_and_slow
```

To start the API:

```bash
python app.py
```

To use the CLI wrapper:

```bash
python run.py demo normal
python run.py api
python run.py train
python run.py all
```

## 14. File Map Summary

| Area | File |
|---|---|
| CLI orchestration | [run.py](run.py) |
| Demo runner | [main.py](main.py) |
| API bootstrap | [app.py](app.py) |
| Input layer | [pipeline/input/loader.py](pipeline/input/loader.py) |
| Feature layer | [pipeline/features/processor.py](pipeline/features/processor.py) |
| Severity layer | [pipeline/severity/scorer.py](pipeline/severity/scorer.py) |
| Severity fallback | [pipeline/severity/model_loader.py](pipeline/severity/model_loader.py) |
| Trust layer | [pipeline/trust/engine.py](pipeline/trust/engine.py) |
| Enforcement layer | [pipeline/enforcement/policy.py](pipeline/enforcement/policy.py) |
| Firewall simulation | [pipeline/firewall/simulator.py](pipeline/firewall/simulator.py) |
| Firewall state | [pipeline/firewall/state.py](pipeline/firewall/state.py) |
| Explainability | [pipeline/explainability/explainer.py](pipeline/explainability/explainer.py) |
| Explain rules | [Test_Model/test_model/explain.py](Test_Model/test_model/explain.py) |
| Shared contracts | [pipeline/utils/models.py](pipeline/utils/models.py) |

## 15. Summary

The POC is a layered, explainable Zero Trust prototype that:

- Loads and normalizes network flow data
- Scores anomalies with AE + IF
- Uses dynamic weighting and percentile normalization
- Updates trust with exponential decay and linear recovery
- Maps trust to allow, throttle, or block behavior
- Simulates firewall side effects and entity state
- Exposes the result through a REST API and CLI demos

If you want the shortest possible operational view, start with [main.py](main.py), [pipeline/severity/scorer.py](pipeline/severity/scorer.py), and [trust_engine.py](trust_engine.py).