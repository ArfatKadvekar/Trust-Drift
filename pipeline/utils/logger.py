"""
pipeline/utils/logger.py
========================
Structured JSON logging for all pipeline layers.

Each layer writes its output to a dedicated JSON file with timestamps and metadata.
Supports debug mode for full trace logging.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Optional
from datetime import datetime
from dataclasses import asdict


class JsonLogger:
    """Structured JSON logger for pipeline layers."""
    
    def __init__(self, log_dir: str = "./logs", debug: bool = False):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.debug = debug
        
    def _get_timestamp(self) -> str:
        return datetime.utcnow().isoformat() + "Z"
    
    def _ensure_serializable(self, obj: Any) -> Any:
        """Convert non-serializable objects to strings."""
        if hasattr(obj, '__dataclass_fields__'):
            return asdict(obj)
        elif hasattr(obj, '__dict__'):
            return str(obj)
        elif isinstance(obj, (list, tuple)):
            return [self._ensure_serializable(item) for item in obj]
        elif isinstance(obj, dict):
            return {k: self._ensure_serializable(v) for k, v in obj.items()}
        elif hasattr(obj, 'value'):  # Enum
            return obj.value
        try:
            json.dumps(obj)
            return obj
        except (TypeError, ValueError):
            return str(obj)
    
    def log_layer(
        self,
        layer_name: str,
        request_id: str,
        output: Any,
        filename: str
    ) -> None:
        """Log output from a pipeline layer."""
        file_path = self.log_dir / filename
        
        entry = {
            "timestamp": self._get_timestamp(),
            "request_id": request_id,
            "layer": layer_name,
            "output": self._ensure_serializable(output)
        }
        
        # Append to file (JSONL format)
        with open(file_path, 'a') as f:
            f.write(json.dumps(entry) + '\n')
        
        if self.debug:
            print(f"[{layer_name}] Logged to {filename}")
    
    def log_input(self, request_id: str, data: dict[str, Any]) -> None:
        """Log input layer."""
        self.log_layer("input", request_id, data, "input.json")
    
    def log_features(self, request_id: str, data: dict[str, Any]) -> None:
        """Log feature processing layer."""
        self.log_layer("features", request_id, data, "features.json")
    
    def log_severity(self, request_id: str, data: dict[str, Any]) -> None:
        """Log severity layer."""
        self.log_layer("severity", request_id, data, "severity.json")
    
    def log_explainability(self, request_id: str, data: dict[str, Any]) -> None:
        """Log explainability layer."""
        self.log_layer("explainability", request_id, data, "explainability.json")
    
    def log_trust(self, request_id: str, data: dict[str, Any]) -> None:
        """Log trust engine layer."""
        self.log_layer("trust", request_id, data, "trust.json")
    
    def log_enforcement(self, request_id: str, data: dict[str, Any]) -> None:
        """Log enforcement layer."""
        self.log_layer("enforcement", request_id, data, "enforcement.json")
    
    def log_firewall(self, request_id: str, data: dict[str, Any]) -> None:
        """Log firewall simulation layer."""
        self.log_layer("firewall", request_id, data, "firewall_logs.json")
    
    def log_debug_trace(self, request_id: str, trace: dict[str, Any]) -> None:
        """Log full debug trace."""
        file_path = self.log_dir / "debug_trace.json"
        
        entry = {
            "timestamp": self._get_timestamp(),
            "request_id": request_id,
            "trace": self._ensure_serializable(trace)
        }
        
        with open(file_path, 'a') as f:
            f.write(json.dumps(entry) + '\n')
    
    def read_logs(
        self,
        filename: str,
        request_id: Optional[str] = None,
        limit: int = 100
    ) -> list[dict[str, Any]]:
        """Read logs from file, optionally filtered by request_id."""
        file_path = self.log_dir / filename
        
        if not file_path.exists():
            return []
        
        logs = []
        with open(file_path, 'r') as f:
            for line in f:
                if not line.strip():
                    continue
                entry = json.loads(line)
                if request_id is None or entry.get('request_id') == request_id:
                    logs.append(entry)
                    if len(logs) >= limit:
                        break
        
        return logs
    
    def clear_logs(self) -> None:
        """Clear all log files."""
        for file in self.log_dir.glob("*.json"):
            file.unlink()
        if self.debug:
            print(f"[logger] Cleared all logs in {self.log_dir}")


# Global logger instance
_logger: Optional[JsonLogger] = None


def get_logger(log_dir: str = "./logs", debug: bool = False) -> JsonLogger:
    """Get or create global logger instance."""
    global _logger
    if _logger is None:
        _logger = JsonLogger(log_dir, debug)
    return _logger


def set_logger(logger: JsonLogger) -> None:
    """Set global logger instance."""
    global _logger
    _logger = logger
