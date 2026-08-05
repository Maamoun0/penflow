import asyncio
import time
from typing import Dict, Callable, Awaitable, Any, Optional
from penflow.core.acp_protocol import ACPMessage
from penflow.utils.logger import get_logger

logger = get_logger("penflow.core.command_bus")

class CommandBus:
    """
    Point-to-Point Command Bus implementing exactly-once execution lock registry semantics.
    """

    def __init__(self):
        self._handlers: Dict[str, Callable[[ACPMessage], Awaitable[Dict[str, Any]]]] = {}
        self._processed_commands: Dict[str, float] = {}  # command_id -> timestamp

    def register_handler(self, actor_address: str, handler: Callable[[ACPMessage], Awaitable[Dict[str, Any]]]):
        self._handlers[actor_address] = handler
        logger.debug(f"[CommandBus] Registered command handler for actor '{actor_address}'")

    async def dispatch(self, target_actor: str, command: ACPMessage) -> Dict[str, Any]:
        if not command.validate():
            logger.error(f"[CommandBus] Invalid command envelope rejected for actor '{target_actor}'")
            return {"status": "REJECTED_INVALID_ENVELOPE"}

        # Command Lock Registry Anti-Duplicate Check
        if command.message_id in self._processed_commands:
            logger.warning(f"[CommandBus] Duplicate command execution rejected: id={command.message_id}")
            return {"status": "REJECTED_DUPLICATE", "message_id": command.message_id}

        handler = self._handlers.get(target_actor)
        if not handler:
            logger.error(f"[CommandBus] Target actor '{target_actor}' not found in command handler registry")
            return {"status": "REJECTED_UNREGISTERED_ACTOR"}

        # Lock command message ID
        self._processed_commands[command.message_id] = time.time()

        try:
            result = await handler(command)
            return result
        except Exception as e:
            logger.error(f"[CommandBus] Execution exception in command handler for '{target_actor}': {str(e)}")
            return {"status": "EXECUTION_FAULT", "error": str(e)}
