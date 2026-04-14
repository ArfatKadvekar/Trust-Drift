"""
app.py
======
FastAPI Application Entry Point

Run with:
    python app.py
    OR
    uvicorn app:app --reload --port 8000
"""

import yaml
import sys
from pathlib import Path

from pipeline.api.server import create_app

# Load configuration
config_path = Path("config.yaml")
if not config_path.exists():
    print(f"Warning: {config_path} not found, using defaults")
    config = {}
else:
    with open(config_path) as f:
        full_config = yaml.safe_load(f)
        config = full_config or {}

# Extract API config
api_config = config.get("api", {})
debug = config.get("debug", False)

# Create app
app = create_app(config=config, debug=debug)

if __name__ == "__main__":
    import uvicorn
    
    host = api_config.get("host", "127.0.0.1")
    port = api_config.get("port", 8000)
    workers = api_config.get("workers", 1)
    
    print(f"Starting Trust-Drift API server...")
    print(f"  Host: {host}")
    print(f"  Port: {port}")
    print(f"  Workers: {workers}")
    print(f"  Debug: {debug}")
    print()
    print(f"API will be available at: http://{host}:{port}")
    print(f"Docs: http://{host}:{port}/docs")
    print()
    
    uvicorn.run(
        "app:app",
        host=host,
        port=port,
        workers=workers,
        reload=debug,
    )
