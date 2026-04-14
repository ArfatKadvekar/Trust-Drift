"""
pipeline/firewall/__init__.py
=============================
Layer 7: Firewall Simulation Layer 🔥

Stateful firewall that acts on enforcement decisions.
Simulates ALLOW, THROTTLE, BLOCK, QUARANTINE actions.

This is CRITICAL for demonstrating real-world Zero Trust behavior in PoC.
"""

from pipeline.firewall.simulator import FirewallSimulator
from pipeline.firewall.state import EntityState

__all__ = ["FirewallSimulator", "EntityState"]
