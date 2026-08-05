from enum import Enum
from penflow.shared.exceptions import DomainError

class RuntimeState(Enum):
    STOPPED = "STOPPED"
    STARTING = "STARTING"
    RUNNING = "RUNNING"
    PAUSING = "PAUSING"
    PAUSED = "PAUSED"
    STOPPING = "STOPPING"
    ERROR = "ERROR"

class RuntimeStateMachine:
    """
    Finite State Machine governing the operational state transitions of the Core Runtime.
    """
    VALID_TRANSITIONS = {
        RuntimeState.STOPPED: {RuntimeState.STARTING},
        RuntimeState.STARTING: {RuntimeState.RUNNING, RuntimeState.ERROR},
        RuntimeState.RUNNING: {RuntimeState.PAUSING, RuntimeState.STOPPING, RuntimeState.ERROR},
        RuntimeState.PAUSING: {RuntimeState.PAUSED, RuntimeState.ERROR},
        RuntimeState.PAUSED: {RuntimeState.RUNNING, RuntimeState.STOPPING, RuntimeState.ERROR},
        RuntimeState.STOPPING: {RuntimeState.STOPPED, RuntimeState.ERROR},
        RuntimeState.ERROR: {RuntimeState.STOPPED}
    }

    def __init__(self):
        self._state = RuntimeState.STOPPED

    @property
    def current_state(self) -> RuntimeState:
        return self._state

    def transition_to(self, target_state: RuntimeState) -> None:
        allowed = self.VALID_TRANSITIONS.get(self._state, set())
        if target_state not in allowed:
            raise DomainError(
                f"[RuntimeStateMachine] Invalid state transition from '{self._state.value}' to '{target_state.value}'"
            )
        self._state = target_state
