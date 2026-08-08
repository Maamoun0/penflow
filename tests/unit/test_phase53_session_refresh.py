import time
import json
import base64
import pytest
from penflow.traffic.session_manager import SessionManager

def test_session_manager_jwt_expiration():
    sm = SessionManager()
    
    # Create non-expired token (valid for 1 hour)
    payload_valid = json.dumps({"sub": "user1", "exp": int(time.time()) + 3600})
    b64_valid = base64.urlsafe_b64encode(payload_valid.encode("utf-8")).decode("utf-8").rstrip("=")
    token_valid = f"eyJhbGciOiJIUzI1NiJ9.{b64_valid}.sig"

    # Create expired token (expired 10 minutes ago)
    payload_exp = json.dumps({"sub": "user1", "exp": int(time.time()) - 600})
    b64_exp = base64.urlsafe_b64encode(payload_exp.encode("utf-8")).decode("utf-8").rstrip("=")
    token_exp = f"eyJhbGciOiJIUzI1NiJ9.{b64_exp}.sig"

    assert sm.is_jwt_expired(token_valid) is False
    assert sm.is_jwt_expired(token_exp) is True

    # Configure session with expired token
    ident = sm.configure_authenticated_session(bearer_token=token_exp)
    retrieved = sm.get_identity(ident.id)
    assert retrieved is not None
    assert retrieved.is_active is False
