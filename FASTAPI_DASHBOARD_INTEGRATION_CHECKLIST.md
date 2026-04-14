# FastAPI Dashboard Integration and Git Upload Checklist

This document makes the repo handoff-ready for Git and frontend dashboard integration.

## 1. What is already covered

1. FastAPI API is available through [app.py](app.py) and [pipeline/api/server.py](pipeline/api/server.py).
2. CORS middleware is enabled and configurable through [config.yaml](config.yaml) under `api.cors`.
3. Dashboard-facing endpoints are implemented:
   1. `POST /analyze`
   2. `GET /health`
   3. `GET /stats`
   4. `GET /alerts`
   5. `GET /firewall-logs`
   6. `GET /entities`
4. Trust, enforcement, and firewall output are returned in one response for easy UI cards/charts.

## 2. Required pre-upload cleanup

Run these commands from repo root before pushing:

```powershell
git rm -r --cached **/__pycache__
git rm --cached *.pyc
git add .
```

Why: `.gitignore` already ignores Python cache files, but tracked cache files remain in index until removed with `--cached`.

## 3. Recommended Git upload flow

```powershell
git status
git add .
git commit -m "docs: add complete guide and dashboard integration setup"
git branch -M main
git remote add origin <YOUR_REPO_URL>
git push -u origin main
```

If `origin` already exists:

```powershell
git remote set-url origin <YOUR_REPO_URL>
git push -u origin main
```

## 4. Dashboard integration setup

## Backend start

```powershell
python app.py
```

Docs should be available at:

- `http://127.0.0.1:8000/docs`

## Frontend API base URL

Set your dashboard app API base URL to:

- `http://127.0.0.1:8000`

## CORS for local dev and production

Edit [config.yaml](config.yaml):

```yaml
api:
  cors:
    allowed_origins:
      - "http://localhost:3000"
      - "http://127.0.0.1:5173"
      - "https://your-dashboard-domain.com"
    allow_credentials: true
    allow_methods: ["*"]
    allow_headers: ["*"]
```

## 5. Minimum dashboard API contract

## Analyze request

`POST /analyze`

```json
{
  "entity_id": "192.168.1.100",
  "feature_vector": [0.12, 0.44, 0.81, 0.06, 0.90, 0.11, 0.33, 0.20, 0.74, 0.57, 0.13, 0.29, 0.40, 0.68, 0.88, 0.31, 0.52, 0.26, 0.79, 0.61, 0.15, 0.19, 0.25, 0.45, 0.66, 0.72, 0.83, 0.92, 0.04, 0.10, 0.17, 0.21, 0.35, 0.47, 0.58, 0.62, 0.69, 0.76, 0.84, 0.93, 0.98],
  "debug": false
}
```

## Analyze response fields for UI

Use these response fields directly in dashboard cards:

1. `summary.severity_score`
2. `summary.trust_score`
3. `summary.zone`
4. `summary.risk_level`
5. `summary.final_action`
6. `summary.allow`
7. `severity.top_anomalous_features`
8. `explainability.attack_pattern`
9. `explainability.verdict`
10. `firewall.latency_ms`

## Polling endpoints for widgets

1. `GET /stats` every 5 to 10 seconds for KPIs.
2. `GET /alerts?min_severity=0.7&limit=50` for alert feed.
3. `GET /firewall-logs?limit=100` for audit table.
4. `GET /entities` for per-entity state panel.

## 6. Production readiness checklist

1. Replace wildcard CORS with explicit origins.
2. Set `debug: false` in [config.yaml](config.yaml).
3. Keep `allow_fallback: true` for demo resilience or set to `false` for strict model dependency.
4. Ensure model artifacts exist in [pipeline/severity/models](pipeline/severity/models) when using real mode.
5. Add a `LICENSE` file to match README badge (MIT).

## 7. Optional next hardening tasks

1. Add request schema validation for `POST /analyze` with Pydantic model.
2. Add API authentication (API key or JWT) before external deployment.
3. Add Dockerfile and healthcheck-based container deployment.
4. Add CI workflow for lint and smoke tests before push.
