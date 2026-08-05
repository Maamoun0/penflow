import uuid
import hashlib
import json
import yaml
from datetime import datetime, timezone
import os
from typing import Any, Dict

def generate_uuid() -> str:
    """Generates a standard UUIDv4 string."""
    return str(uuid.uuid4())

def compute_sha256(content: bytes | str) -> str:
    """Computes SHA-256 hex digest for string or byte content."""
    if isinstance(content, str):
        content = content.encode("utf-8")
    return hashlib.sha256(content).hexdigest()

def serialize_json(data: Any) -> str:
    """Serializes data to formatted JSON string."""
    return json.dumps(data, default=str, ensure_ascii=False)

def deserialize_json(json_str: str) -> Any:
    """Deserializes JSON string to Python object."""
    return json.loads(json_str)

def load_yaml_file(file_path: str) -> Dict[str, Any]:
    """Reads and parses a YAML file safely."""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"YAML file not found: {file_path}")
    with open(file_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}

def get_utc_timestamp() -> float:
    """Returns current UTC timestamp in float seconds."""
    return datetime.now(timezone.utc).timestamp()

def ensure_dir(dir_path: str) -> str:
    """Ensures directory exists and returns absolute path."""
    os.makedirs(dir_path, exist_ok=True)
    return os.path.abspath(dir_path)
