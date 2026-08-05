import pytest
import tempfile
import os
from penflow.storage.sqlite_db import SQLiteStorage
from penflow.domain.models import Target, Program, Asset

def test_sqlite_db_init_and_tables():
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path = os.path.join(tmp_dir, "penflow_test.db")
        db = SQLiteStorage(db_path=db_path)
        assert os.path.exists(db_path) is True

def test_sqlite_target_and_program_persistence():
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path = os.path.join(tmp_dir, "penflow_test.db")
        db = SQLiteStorage(db_path=db_path)
        
        prog = Program(name="HackerOne Target Program", platform="HackerOne")
        db.save_program(prog)
        
        fetched_prog = db.get_program(prog.id)
        assert fetched_prog is not None
        assert fetched_prog.name == "HackerOne Target Program"
        
        target = Target(program_id=prog.id, domain="target.com")
        db.save_target(target)
        
        fetched_target = db.get_target(target.id)
        assert fetched_target is not None
        assert fetched_target.domain == "target.com"

def test_sqlite_asset_persistence():
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path = os.path.join(tmp_dir, "penflow_test.db")
        db = SQLiteStorage(db_path=db_path)
        
        asset = Asset(target_id="tgt_123", asset_type="subdomain", value="api.target.com")
        db.save_asset(asset)
        
        assets = db.list_assets_for_target("tgt_123")
        assert len(assets) == 1
        assert assets[0].value == "api.target.com"
