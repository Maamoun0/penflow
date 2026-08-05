from enum import Enum
from typing import Callable, List, Awaitable, Any
import asyncio
from penflow.core.state_machine import RuntimeStateMachine, RuntimeState
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.core.lifecycle")

class AgentLifecycleState(Enum):
    UNINITIALIZED = "UNINITIALIZED"
    INITIALIZED = "INITIALIZED"
    REGISTERED = "REGISTERED"
    ADVERTISING = "ADVERTISING"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    CLEANUP = "CLEANUP"
    TERMINATED = "TERMINATED"

class AgentStateMachine:
    """
    Legacy Agent State Machine wrapper.
    """
    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self._state = AgentLifecycleState.INITIALIZED

    @property
    def state(self) -> AgentLifecycleState:
        return self._state

    def transition_to(self, new_state: AgentLifecycleState):
        logger.debug(f"[AgentStateMachine] Agent '{self.agent_id}' transition -> {new_state.value}")
        self._state = new_state

class LifecycleManager:
    """
    Lifecycle Manager executing startup and shutdown hook callbacks across runtime state changes.
    """
    def __init__(self, state_machine: RuntimeStateMachine):
        self.state_machine = state_machine
        self._startup_hooks: List[Callable[[], Awaitable[None]]] = []
        self._shutdown_hooks: List[Callable[[], Awaitable[None]]] = []

    def on_startup(self, hook: Callable[[], Awaitable[None]]) -> None:
        self._startup_hooks.append(hook)

    def on_shutdown(self, hook: Callable[[], Awaitable[None]]) -> None:
        self._shutdown_hooks.append(hook)

    async def start(self) -> None:
        self.state_machine.transition_to(RuntimeState.STARTING)
        logger.info("[LifecycleManager] Starting runtime components...")
        for hook in self._startup_hooks:
            if asyncio.iscoroutinefunction(hook):
                await hook()
            else:
                hook()
        self.state_machine.transition_to(RuntimeState.RUNNING)
        logger.info("[LifecycleManager] Runtime is RUNNING.")

    async def stop(self) -> None:
        if self.state_machine.current_state in [RuntimeState.STOPPING, RuntimeState.STOPPED]:
            return
        self.state_machine.transition_to(RuntimeState.STOPPING)
        logger.info("[LifecycleManager] Stopping runtime components...")
        for hook in reversed(self._shutdown_hooks):
            if asyncio.iscoroutinefunction(hook):
                await hook()
            else:
                hook()
        self.state_machine.transition_to(RuntimeState.STOPPED)
        logger.info("[LifecycleManager] Runtime is STOPPED.")
