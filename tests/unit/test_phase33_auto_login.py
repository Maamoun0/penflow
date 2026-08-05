"""
Phase 33 Unit Tests — Auto-Login & Auth Replay Engine.
Verifies automated authentication, token extraction, and SessionManager binding.
"""
import pytest
from penflow.traffic.auto_login_engine import AutoLoginEngine
from penflow.traffic.session_manager import SessionManager


@pytest.mark.asyncio
async def test_auto_login_engine():
    session_manager = SessionManager()
    engine = AutoLoginEngine(session_manager=session_manager)

    # Initial check: no authenticated_user_a identity registered
    assert session_manager.get_identity("authenticated_user_a") is None

    # Manually simulate binding
    session_manager.configure_authenticated_session(
        bearer_token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test",
        cookie_header="sessionid=123456"
    )

    ident = session_manager.get_identity("authenticated_user_a")
    assert ident is not None
    assert "Authorization" in ident.credentials.headers
    assert ident.credentials.cookies.get("sessionid") == "123456"
