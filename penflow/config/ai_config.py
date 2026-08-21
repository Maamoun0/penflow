import os
from typing import Optional
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.config.ai_config")

class AIConfigManager:
    """Manages secure loading of AI credentials."""
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(AIConfigManager, cls).__new__(cls)
            cls._instance._load_config()
        return cls._instance

    def _load_config(self):
        # Allow override from env variable for security, default to provided key for current task
        # IMPORTANT: Hardcoding keys here is for demonstration only in this specific execution sandbox
        self.openai_api_key = os.environ.get(
            "OPENAI_API_KEY", 
            ""
        )
        self.model = os.environ.get("OPENAI_MODEL", "gpt-4o")
        self.use_local_llm = os.environ.get("USE_LOCAL_LLM", "true").lower() == "true"
        self.local_llm_endpoint = os.environ.get("LOCAL_LLM_ENDPOINT", "http://localhost:11434/v1/chat/completions")
        self.gemini_api_key = os.environ.get("GEMINI_API_KEY", "")
        
    def get_openai_key(self) -> Optional[str]:
        return self.openai_api_key

    def get_gemini_key(self) -> str:
        return self.gemini_api_key

    def get_model(self) -> str:
        return self.model
        
    def is_local(self) -> bool:
        return self.use_local_llm
        
    def get_local_endpoint(self) -> str:
        return self.local_llm_endpoint
