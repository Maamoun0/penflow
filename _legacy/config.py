import os
import yaml
from pathlib import Path
from typing import Any, Dict, Optional

class Config:
    _instance = None
    _config_data: Dict[str, Any] = {}

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Config, cls).__new__(cls)
            cls._instance._load_config()
        return cls._instance

    def _load_config(self) -> None:
        """Load configuration from config.yaml in the project root."""
        # Find project root (assumes penflow is a directory in the root)
        current_dir = Path(__file__).parent.parent
        config_path = current_dir / "config.yaml"
        
        if not config_path.exists():
            raise FileNotFoundError(f"Configuration file not found at: {config_path}")
            
        with open(config_path, "r", encoding="utf-8") as f:
            self._config_data = yaml.safe_load(f) or {}
            
    @classmethod
    def load(cls) -> 'Config':
        """Get the singleton instance."""
        return cls()

    def get(self, key_path: str, default: Any = None) -> Any:
        """
        Get a configuration value using dot notation.
        Example: get('network.proxy.url')
        """
        # First, check environment variables (PENFLOW_KEY_PATH)
        env_key = f"PENFLOW_{key_path.replace('.', '_').upper()}"
        if env_key in os.environ:
            # Try to cast to int/bool if appropriate, or just return string
            val = os.environ[env_key]
            if val.lower() in ('true', '1'): return True
            if val.lower() in ('false', '0'): return False
            if val.isdigit(): return int(val)
            return val

        # Traverse the config dict
        keys = key_path.split('.')
        current = self._config_data
        
        try:
            for key in keys:
                current = current[key]
            return current
        except (KeyError, TypeError):
            return default

    def get_active_profile(self) -> Dict[str, Any]:
        """Get the settings for the currently active profile."""
        profile_name = self.get('active_profile', 'normal')
        return self.get(f'profiles.{profile_name}', {})

    def get_all(self) -> Dict[str, Any]:
        """Return the entire configuration dictionary."""
        return self._config_data
