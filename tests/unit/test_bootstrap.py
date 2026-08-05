import pytest
import os
from penflow.infrastructure.config import ConfigManager
from penflow.infrastructure.logger import get_logger, StructuredJSONFormatter
from penflow.shared.exceptions import (
    PenFlowError, ConfigurationError, ValidationError,
    InfrastructureError, DomainError, ConnectorError, PluginError
)
from penflow.shared.utils import (
    generate_uuid, compute_sha256, serialize_json,
    deserialize_json, load_yaml_file, get_utc_timestamp, ensure_dir
)

def test_config_manager():
    config_mgr = ConfigManager(settings_path="config/settings.yaml", features_path="config/features.yaml")
    assert config_mgr.settings.project.name == "PenFlow"
    assert config_mgr.settings.project.version == "0.1.0"
    assert config_mgr.settings.workers.max_workers == 8
    assert config_mgr.features.ai["enabled"] is False

def test_logger_json_formatting(capsys):
    logger = get_logger("penflow.test_json", format_type="json")
    logger.info("Test structured logging message")
    captured = capsys.readouterr()
    assert "Test structured logging message" in captured.out
    assert "timestamp" in captured.out
    assert "penflow.test_json" in captured.out

def test_exceptions_hierarchy():
    with pytest.raises(PenFlowError):
        raise ConfigurationError("Invalid config")
    with pytest.raises(PenFlowError):
        raise ValidationError("Invalid payload")
    with pytest.raises(PenFlowError):
        raise InfrastructureError("DB down")

def test_utilities_helpers(tmp_path):
    # UUID
    uid = generate_uuid()
    assert len(uid) == 36
    
    # SHA256
    hash_val = compute_sha256("test_content")
    assert len(hash_val) == 64

    # JSON
    data = {"key": "value"}
    json_str = serialize_json(data)
    assert deserialize_json(json_str) == data

    # Timestamp
    ts = get_utc_timestamp()
    assert ts > 0

    # Ensure Dir
    target_dir = str(tmp_path / "nested" / "dir")
    abs_path = ensure_dir(target_dir)
    assert os.path.exists(abs_path)
