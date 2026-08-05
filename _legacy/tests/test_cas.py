import pytest
import os
import tempfile
from penflow.storage.cas import ContentAddressableStorage

def test_cas_store_and_retrieve():
    with tempfile.TemporaryDirectory() as tmp_dir:
        cas = ContentAddressableStorage(storage_dir=tmp_dir)
        
        # Test string payload
        data = b"Hello PenFlow CAS Security Storage"
        content_hash = cas.store(data)
        
        assert len(content_hash) == 64  # SHA-256 hex string length
        assert cas.exists(content_hash) is True
        
        retrieved = cas.retrieve(content_hash)
        assert retrieved == data

def test_cas_deduplication():
    with tempfile.TemporaryDirectory() as tmp_dir:
        cas = ContentAddressableStorage(storage_dir=tmp_dir)
        
        data = b"Duplicate Content Payload"
        hash1 = cas.store(data)
        hash2 = cas.store(data)
        
        assert hash1 == hash2

def test_cas_missing_hash():
    with tempfile.TemporaryDirectory() as tmp_dir:
        cas = ContentAddressableStorage(storage_dir=tmp_dir)
        fake_hash = "a" * 64
        assert cas.exists(fake_hash) is False
        assert cas.retrieve(fake_hash) is None
