"""
PenFlow Stateful Traffic & Multi-Session Engine
Provides authenticated session management, asynchronous HTTP interaction,
and differential response analysis for advanced security research.
"""

from penflow.traffic.models import (
    IdentityType,
    AuthCredentials,
    Identity,
    TrafficRequest,
    TrafficResponse,
    TrafficExchange,
    DiffResult,
)

__all__ = [
    "IdentityType",
    "AuthCredentials",
    "Identity",
    "TrafficRequest",
    "TrafficResponse",
    "TrafficExchange",
    "DiffResult",
]
