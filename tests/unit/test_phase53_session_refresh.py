import time
import json
import base64
import pytest
from penflow.traffic.session_manager import SessionManager

def test_session_manager_jwt_expiration_and_auto_refresh():
    sm = SessionManager()
    
    # Create non-expired token
    payload_valid = json.dumps({"sub": "user1", "exp": int(time.time()) + 3600})
    b64_valid = base64.urlsafe_b64encode(payload_valid.encode("utf-8")).decode("utf-8").rstrip("=")
    token_valid = f"eyJhbGciOiJIUzI1NiJ9.{b64_valid}.sig"

    # Create expired token
    payload_exp = json.dumps({"sub": "user1", "exp": int(time.time()) - 600})
    b64_exp = base64.urlsafe_b64encode(payload_exp.encode("utf-8")).decode("utf-8").rstrip("=")
    token_exp = f"eyJhbGciOiJIUzI1NiJ9.{b64_exp}.sig"

    assert sm.is_jwt_expired(token_valid) is False
    assert sm.is_jwt_expired(token_exp) is True

    # Register refresh callback that returns token_valid when invoked
    def mock_refresh():
        return token_valid

    ident = sm.configure_authenticated_session(bearer_token=token_exp, refresh_callback=mock_refresh)
    
    # Retrieval should trigger mock_refresh() and renew identity to active state with token_valid
    retrieved = sm.get_identity(ident.id)
    assert retrieved is not None
    assert retrieved.is_active is True
    assert retrieved.credentials.bearer_token == token_valid
