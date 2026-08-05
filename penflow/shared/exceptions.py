class PenFlowError(Exception):
    """Base exception for all PenFlow platform errors."""
    pass

class ConfigurationError(PenFlowError):
    """Raised when configuration loading or validation fails."""
    pass

class ValidationError(PenFlowError):
    """Raised when data model or message schema validation fails."""
    pass

class InfrastructureError(PenFlowError):
    """Raised when storage, database, or network infrastructure fails."""
    pass

class DomainError(PenFlowError):
    """Raised when domain rule invariants are violated."""
    pass

class ConnectorError(PenFlowError):
    """Raised when external platform connector operations fail."""
    pass

class PluginError(PenFlowError):
    """Raised when plugin execution or sandboxing fails."""
    pass
