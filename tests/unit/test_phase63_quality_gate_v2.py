"""
Unit tests for Quality Gate Gate 2 (PoC verification status enforcement).
Verifies that 401/403 responses are rejected from PoC success.
"""
import pytest
from unittest.mock import AsyncMock, MagicMock
from penflow.reporting.poc_generator import PoCGenerator


@pytest.mark.asyncio
async def test_poc_generator_rejects_401(monkeypatch):
    class MockResp:
        status_code = 401
    async def mock_req(*args, **kwargs):
        return MockResp()
    
    monkeypatch.setattr("httpx.AsyncClient.request", mock_req)
    poc_gen = PoCGenerator()
    
    exchange = {
        "target_url": "https://example.com/api/admin",
        "request": {"method": "GET", "url": "https://example.com/api/admin"}
    }
    res = await poc_gen.verify_poc_execution(exchange)
    assert res is False


@pytest.mark.asyncio
async def test_poc_generator_rejects_403(monkeypatch):
    class MockResp:
        status_code = 403
    async def mock_req(*args, **kwargs):
        return MockResp()

    monkeypatch.setattr("httpx.AsyncClient.request", mock_req)
    poc_gen = PoCGenerator()

    exchange = {
        "target_url": "https://example.com/api/admin",
        "request": {"method": "GET", "url": "https://example.com/api/admin"}
    }
    res = await poc_gen.verify_poc_execution(exchange)
    assert res is False


@pytest.mark.asyncio
async def test_poc_generator_accepts_200(monkeypatch):
    class MockResp:
        status_code = 200
    async def mock_req(*args, **kwargs):
        return MockResp()

    monkeypatch.setattr("httpx.AsyncClient.request", mock_req)
    poc_gen = PoCGenerator()

    exchange = {
        "target_url": "https://example.com/api/data",
        "request": {"method": "GET", "url": "https://example.com/api/data"}
    }
    res = await poc_gen.verify_poc_execution(exchange)
    assert res is True


@pytest.mark.asyncio
async def test_poc_generator_accepts_302_redirect(monkeypatch):
    class MockResp:
        status_code = 302
    async def mock_req(*args, **kwargs):
        return MockResp()

    monkeypatch.setattr("httpx.AsyncClient.request", mock_req)
    poc_gen = PoCGenerator()

    exchange = {
        "target_url": "https://example.com/login",
        "request": {"method": "GET", "url": "https://example.com/login"}
    }
    res = await poc_gen.verify_poc_execution(exchange)
    assert res is True
