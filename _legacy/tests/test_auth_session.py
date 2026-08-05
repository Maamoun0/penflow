import pytest
from penflow.network.auth_session_manager import AuthSessionManager, AuthProfile
from penflow.scanner.vuln_detectors.idor_bola import IDORDetector

def test_auth_session_manager():
    manager = AuthSessionManager()
    manager.set_profile("user_a", headers={"Authorization": "Bearer token_a"}, user_id="101")
    manager.set_profile("user_b", headers={"Authorization": "Bearer token_b"}, user_id="102")
    
    assert manager.get_profile("user_a").user_id == "101"
    assert manager.get_headers_for("user_a") == {"Authorization": "Bearer token_a"}
    assert manager.get_headers_for("user_b") == {"Authorization": "Bearer token_b"}
    
    data = manager.to_dict()
    restored = AuthSessionManager.from_dict(data)
    assert restored.get_headers_for("user_a") == {"Authorization": "Bearer token_a"}

@pytest.mark.asyncio
async def test_idor_detector_name():
    detector = IDORDetector()
    assert detector.name() == "idor_detector"
    assert "BOLA" in detector.supported_types
