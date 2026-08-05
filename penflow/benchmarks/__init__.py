"""
PenFlow Benchmarking Package
Provides standalone local mock target server for testing multi-session security agents
against IDOR, BFLA, Mass Assignment, GraphQL, and Race Conditions.
"""

from penflow.benchmarks.mock_target_server import MockTargetServer

__all__ = ["MockTargetServer"]
