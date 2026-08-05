import logging
import sys
import json
from datetime import datetime, timezone
from typing import Dict, Any, Optional

class StructuredJSONFormatter(logging.Formatter):
    """
    JSON Log Formatter for PenFlow SROS.
    Outputs: {timestamp, level, component, correlation_id, message}
    """
    def format(self, record: logging.LogRecord) -> str:
        log_entry: Dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
            "level": record.levelname,
            "component": record.name,
            "correlation_id": getattr(record, "correlation_id", "none"),
            "message": record.getMessage()
        }
        return json.dumps(log_entry, ensure_ascii=False)

_loggers: Dict[str, logging.Logger] = {}

def get_logger(name: str = "penflow", format_type: str = "json") -> logging.Logger:
    if name in _loggers:
        return _loggers[name]

    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        if format_type.lower() == "json":
            formatter = StructuredJSONFormatter()
        else:
            formatter = logging.Formatter(
                '[%(asctime)s] [%(levelname)s] [%(name)s] [corr_id=%(correlation_id)s]: %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    _loggers[name] = logger
    return logger

def set_log_level(level: str):
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    for logger in _loggers.values():
        logger.setLevel(numeric_level)
