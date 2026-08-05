from penflow.shared.exceptions import PenFlowError

class CapabilityError(PenFlowError):
    """Base exception for capability framework failures."""
    pass

class CapabilityNotFoundError(CapabilityError):
    """Raised when a requested capability cannot be resolved."""
    pass

class CapabilityConflictError(CapabilityError):
    """Raised when conflicting capabilities are scheduled together."""
    pass

class CapabilityDependencyError(CapabilityError):
    """Raised when capability requirements/dependencies are unfulfilled."""
    pass
