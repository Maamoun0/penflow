import pytest
from penflow.infrastructure.config import Config, get_config
from penflow.infrastructure.logger import get_logger, set_log_level
from penflow.infrastructure.container import Container

def test_infrastructure_config():
    config = get_config()
    assert config.app_name == "PenFlow SROS"
    assert config.environment in ["development", "staging", "production"]
    assert config.max_worker_concurrency > 0

def test_infrastructure_logger():
    logger = get_logger("penflow.test")
    assert logger is not None
    set_log_level("DEBUG")

def test_infrastructure_container():
    container = Container()
    container.register("config", get_config())
    
    resolved_config = container.resolve("config")
    assert resolved_config.app_name == "PenFlow SROS"
    
    with pytest.raises(KeyError):
        container.resolve("non_existent_service")
