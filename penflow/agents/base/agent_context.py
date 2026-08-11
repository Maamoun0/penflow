from dataclasses import dataclass, field
from typing import Dict, Any, Optional
import logging
from penflow.core.context import ExecutionContext, CancellationToken
from penflow.knowledge.knowledge_store import KnowledgeStore

@dataclass
class AgentContext:
    """
    Runtime execution context provided to every agent.
    Gives access to central KnowledgeStore, ExecutionContext, Logger, Config, and Shared Services.
    """
    knowledge_store: KnowledgeStore
    execution_context: ExecutionContext
    logger: logging.Logger
    config: Dict[str, Any] = field(default_factory=dict)
    cancellation_token: CancellationToken = field(default_factory=CancellationToken)
    shared_services: Dict[str, Any] = field(default_factory=dict)
