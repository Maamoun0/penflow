import httpx
import json
from typing import Dict, Any, List
from penflow.infrastructure.logger import get_logger
from penflow.config.ai_config import AIConfigManager
from penflow.intelligence.state_manager import ExploitStateStore, StateFact

logger = get_logger("penflow.intelligence.ai_brain")

class AIBrainStrategist:
    """
    Interfaces with OpenAI LLMs to generate dynamic, novel exploit chains 
    based on the current StateStore memory.
    """
    def __init__(self, state_store: ExploitStateStore):
        self.state_store = state_store
        self.config = AIConfigManager()
        if self.config.is_local():
            self.api_url = self.config.get_local_endpoint()
            logger.info(f"[AIBrain] Configured to use Local LLM at {self.api_url}")
        elif self.config.get_gemini_key():
            self.api_url = "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"
            logger.info("[AIBrain] Configured to use Google AI Studio (Gemini) API")
        else:
            self.api_url = "https://api.openai.com/v1/chat/completions"
            logger.info("[AIBrain] Configured to use OpenAI API")

    def _build_prompt(self, facts: List[StateFact]) -> str:
        prompt = (
            "You are an elite Bug Bounty Hunter and Autonomous Exploit Chaining Engine.\n"
            "Your goal is to analyze the following discovered state facts from a live security scan, "
            "and determine if a multi-step exploit chain can be constructed.\n\n"
            "Here is the current state memory:\n"
        )
        for i, fact in enumerate(facts):
            prompt += f"{i+1}. Fact: '{fact.key}', Value: '{fact.value}', Asset: '{fact.asset}'\n"
            
        prompt += (
            "\nAnalyze the facts and propose EXACTLY ONE next exploitation step if a chain is possible. "
            "If no chain is possible, return an empty array.\n"
            "You must output YOUR ENTIRE RESPONSE as a valid JSON array of tasks matching this schema exactly, and nothing else:\n"
            "[\n"
            "  {\n"
            "    \"agent_name\": \"<The target CapabilityAgent class name (e.g. AccountTakeoverCapabilityAgent, OAuthJWTCapabilityAgent, SSRFCapabilityAgent)>\",\n"
            "    \"capability\": \"<The specific capability to run>\",\n"
            "    \"asset\": \"<The target domain>\",\n"
            "    \"context_data\": { <Key-value pairs to pass to the agent, e.g. target_email, redirect_url> },\n"
            "    \"reasoning\": \"<Your expert reasoning for this chain>\"\n"
            "  }\n"
            "]\n"
        )
        return prompt

    async def analyze_state_and_strategize(self) -> List[Dict[str, Any]]:
        """Queries the LLM and returns a list of tasks to dispatch."""
        key = self.config.get_openai_key()
        gemini_key = self.config.get_gemini_key()
        is_local = self.config.is_local()
        
        if gemini_key:
            key = gemini_key
        elif not is_local and (not key or not key.startswith("sk-")):
            logger.error("[AIBrain] Invalid or missing OpenAI API Key for remote usage.")
            return []

        # Gather all current facts
        all_facts = []
        # Accessing private dict for full state dump safely
        async with self.state_store._lock:
            for key, facts_list in self.state_store._store.items():
                all_facts.extend(facts_list)

        if not all_facts:
            logger.info("[AIBrain] No facts in StateStore to analyze.")
            return []

        prompt = self._build_prompt(all_facts)
        logger.debug(f"[AIBrain] Sending {len(all_facts)} facts to OpenAI for strategizing...")

        headers = {
            "Content-Type": "application/json"
        }
        if not is_local:
            headers["Authorization"] = f"Bearer {key}"
        
        # When using Ollama locally, specify a model like "qwen3-coder:30b"
        if is_local:
            model = "qwen3-coder:30b"
        elif gemini_key:
            model = "gemini-2.5-flash"
        else:
            model = self.config.get_model()
        
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": "You are a specialized security agent. Output strictly valid JSON."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.2, # Low temperature for more deterministic JSON
            "response_format": { "type": "json_object" } # Force JSON mode if model supports it, but fallback to manual parsing
        }
        
        # Override response format for older models, let's just stick to text and parse it
        payload["response_format"] = {"type": "text"}
        
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                resp = await client.post(self.api_url, headers=headers, json=payload)
                if resp.status_code != 200:
                    logger.error(f"[AIBrain] Error calling LLM API: Status {resp.status_code} - {resp.text}")
                    return []
                data = resp.json()
                
                content = data["choices"][0]["message"]["content"].strip()
                
                # Cleanup markdown formatting if present
                if content.startswith("```json"):
                    content = content[7:]
                if content.startswith("```"):
                    content = content[3:]
                if content.endswith("```"):
                    content = content[:-3]
                    
                strategy = json.loads(content.strip())
                if isinstance(strategy, dict) and "tasks" in strategy: # In case it returns an object with a tasks array
                    return strategy["tasks"]
                if isinstance(strategy, list):
                    return strategy
                return []
                
        except json.JSONDecodeError as e:
            logger.error(f"[AIBrain] Failed to parse LLM JSON output: {e}\nRaw Output: {content}")
        except Exception as e:
            logger.error(f"[AIBrain] Error calling OpenAI API: {e}")
            
        return []
