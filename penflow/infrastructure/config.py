import os
from pydantic import BaseModel, Field
from penflow.shared.utils import load_yaml_file
from penflow.shared.exceptions import ConfigurationError

class ProjectSettings(BaseModel):
    name: str = "PenFlow"
    version: str = "0.1.0"

class DatabaseSettings(BaseModel):
    sqlite: str = "storage/database.db"

class LoggingSettings(BaseModel):
    level: str = "INFO"
    format: str = "json"

class WorkerSettings(BaseModel):
    max_workers: int = 8

class Settings(BaseModel):
    project: ProjectSettings = Field(default_factory=ProjectSettings)
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)
    workers: WorkerSettings = Field(default_factory=WorkerSettings)

class Features(BaseModel):
    ai: dict = Field(default_factory=lambda: {"enabled": False})
    learning: dict = Field(default_factory=lambda: {"enabled": False})
    playwright: dict = Field(default_factory=lambda: {"enabled": False})
    connectors: dict = Field(default_factory=lambda: {"hackerone": False, "bugcrowd": False})

class ConfigManager:
    """
    Configuration Manager reading settings.yaml and features.yaml.
    """
    def __init__(self, settings_path: str = "config/settings.yaml", features_path: str = "config/features.yaml"):
        self.settings_path = settings_path
        self.features_path = features_path
        self.settings = self._load_settings()
        self.features = self._load_features()

    def _load_settings(self) -> Settings:
        try:
            if os.path.exists(self.settings_path):
                data = load_yaml_file(self.settings_path)
                return Settings(**data)
            return Settings()
        except Exception as e:
            raise ConfigurationError(f"Failed to load settings from '{self.settings_path}': {str(e)}")

    def _load_features(self) -> Features:
        try:
            if os.path.exists(self.features_path):
                data = load_yaml_file(self.features_path)
                return Features(**data)
            return Features()
        except Exception as e:
            raise ConfigurationError(f"Failed to load features from '{self.features_path}': {str(e)}")

# Legacy compatibility helper
class Config(BaseModel):
    app_name: str = "PenFlow SROS"
    environment: str = "development"
    log_level: str = "INFO"
    db_path: str = "data/penflow.db"
    cas_storage_dir: str = "data/cas"
    acp_signing_secret: str = "penflow_secret_key"
    max_worker_concurrency: int = 20
    max_llm_budget_usd: float = 50.0

def get_config() -> Config:
    return Config()
