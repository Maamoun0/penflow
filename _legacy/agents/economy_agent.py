from typing import Dict, Any
from penflow.agents.base_agent import BaseSwarmAgent
from penflow.utils.logger import get_logger

logger = get_logger("penflow.agents.economy")

class EconomyAgent(BaseSwarmAgent):
    """
    Economy Agent: Resource & LLM Router.
    Responsible for selecting the most cost-effective and performant LLM or execution engine
    for each specific task (e.g. Local LLM vs Reasoning LLM vs Fast Script).
    """

    @property
    def agent_name(self) -> str:
        return "EconomyAgent"

    @property
    def role(self) -> str:
        return "ResourceRouter"

    async def route_task(self, task_description: Dict[str, Any]) -> Dict[str, Any]:
        """
        Determines the optimal LLM / Model routing for a given task.
        """
        task_type = task_description.get("task_type", "general")
        data_size = task_description.get("data_size_bytes", 0)
        
        selected_model = "local_llama3"
        provider = "ollama"
        reason = "Default fast local processing"
        
        if task_type in ("strategic_planning", "complex_reasoning"):
            selected_model = "gemini-3.6-flash"
            provider = "cloud_api"
            reason = "High-level strategic reasoning requires advanced Cloud LLM."
        elif task_type == "code_analysis" and data_size > 10000:
            selected_model = "claude-3-5-sonnet"
            provider = "cloud_api"
            reason = "Deep source code analysis requires large context window Cloud LLM."
        elif task_type in ("summarization", "pattern_matching", "recon_parsing"):
            selected_model = "local_mistral"
            provider = "ollama"
            reason = "Routine parsing & summarization handled locally at zero cost."
            
        routing = {
            "task_type": task_type,
            "selected_model": selected_model,
            "provider": provider,
            "reason": reason
        }
        
        logger.info(f"[EconomyAgent] Routed {task_type} -> {selected_model} ({provider})")
        await self.publish_event("TASK_ROUTED", routing)
        return routing

    async def process_task(self, task_data: Dict[str, Any]) -> Dict[str, Any]:
        return await self.route_task(task_data)
