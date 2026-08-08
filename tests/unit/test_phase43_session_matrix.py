import pytest
import pytest_asyncio
import time
from penflow.auth.account_pool import (
    AuthAccount,
    SessionMatrixManager,
    AutoReplayMatrixEngine,
    RoleType
)

def test_session_matrix_registration_and_rotation():
    matrix = SessionMatrixManager()
    acc_a1 = AuthAccount("user_a_1", "alice1", "pass1", bearer_token="token_a1")
    acc_a2 = AuthAccount("user_a_2", "alice2", "pass2", bearer_token="token_a2")
    acc_b1 = AuthAccount("user_b_1", "bob1", "pass1", bearer_token="token_b1")
    acc_admin = AuthAccount("admin_1", "admin", "pass_admin", bearer_token="token_admin")

    matrix.register_account(RoleType.USER_A, acc_a1)
    matrix.register_account(RoleType.USER_A, acc_a2)
    matrix.register_account(RoleType.USER_B, acc_b1)
    matrix.register_account(RoleType.ADMIN, acc_admin)

    # Initial session for User A
    session = matrix.get_session(RoleType.USER_A)
    assert session.account_id == "user_a_1"

    # Rotation should cycle to user_a_2 to bypass rate limit
    rotated = matrix.rotate_session(RoleType.USER_A)
    assert rotated.account_id == "user_a_2"

    # Rotates back to user_a_1
    rotated_again = matrix.rotate_session(RoleType.USER_A)
    assert rotated_again.account_id == "user_a_1"

    # User B & Admin
    assert matrix.get_session(RoleType.USER_B).account_id == "user_b_1"
    assert matrix.get_session(RoleType.ADMIN).account_id == "admin_1"

@pytest.mark.asyncio
async def test_auto_replay_matrix_idor_differential():
    matrix = SessionMatrixManager()
    acc_a = AuthAccount("user_a", "alice", "pass", bearer_token="token_alice")
    acc_b = AuthAccount("user_b", "bob", "pass", bearer_token="token_bob")
    matrix.register_account(RoleType.USER_A, acc_a)
    matrix.register_account(RoleType.USER_B, acc_b)

    replayer = AutoReplayMatrixEngine(matrix)

    # Mock custom replay by asserting matrix roles snapshot
    roles = matrix.get_all_matrix_roles()
    assert roles["user_a"].bearer_token == "token_alice"
    assert roles["user_b"].bearer_token == "token_bob"
    assert roles["anonymous"].account_id == "anon"
