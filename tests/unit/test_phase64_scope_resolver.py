"""
Unit test suite for Phase 64: ScopePatternResolver Wildcard Pattern Resolution Engine.
"""
import pytest
from unittest.mock import AsyncMock, patch
from penflow.recon.scope_resolver import ScopePatternResolver


def test_extract_root_domain_basic():
    resolver = ScopePatternResolver()
    assert resolver.extract_root_domain("example.com") == "example.com"
    assert resolver.extract_root_domain("sub.example.com") == "example.com"
    assert resolver.extract_root_domain("*.example.com") == "example.com"
    assert resolver.extract_root_domain("prod-*.example.com") == "example.com"
    assert resolver.extract_root_domain("https://api.test.org/v1") == "test.org"


def test_extract_root_domain_multi_segment_tlds():
    resolver = ScopePatternResolver()
    assert resolver.extract_root_domain("prod-*.nubank.com.br") == "nubank.com.br"
    assert resolver.extract_root_domain("prod-*.nu.com.mx") == "nu.com.mx"
    assert resolver.extract_root_domain("prod-*.nu.com.co") == "nu.com.co"
    assert resolver.extract_root_domain("app.service.co.uk") == "service.co.uk"


def test_filter_by_pattern():
    resolver = ScopePatternResolver()
    discovered = [
        "prod-api.nubank.com.br",
        "prod-auth.nubank.com.br",
        "dev-api.nubank.com.br",
        "stg-web.nubank.com.br",
        "prod-dashboard.nubank.com.br"
    ]
    matched = resolver.filter_by_pattern("prod-*.nubank.com.br", discovered)
    assert matched == ["prod-api.nubank.com.br", "prod-auth.nubank.com.br", "prod-dashboard.nubank.com.br"]
    assert "dev-api.nubank.com.br" not in matched
    assert "stg-web.nubank.com.br" not in matched


@pytest.mark.asyncio
async def test_resolve_scope_no_wildcard():
    resolver = ScopePatternResolver()
    res = await resolver.resolve_scope("api.target.com")
    assert res == ["api.target.com"]


@pytest.mark.asyncio
async def test_resolve_scope_with_wildcard():
    mock_crt = AsyncMock()
    mock_crt.fetch_subdomains.return_value = [
        "prod-api.nubank.com.br",
        "prod-auth.nubank.com.br",
        "staging-api.nubank.com.br"
    ]
    resolver = ScopePatternResolver(crt_client=mock_crt)
    res = await resolver.resolve_scope("prod-*.nubank.com.br")

    mock_crt.fetch_subdomains.assert_called_once_with("nubank.com.br")
    assert res == ["prod-api.nubank.com.br", "prod-auth.nubank.com.br"]
    assert "staging-api.nubank.com.br" not in res


@pytest.mark.asyncio
async def test_resolve_scope_fallback_when_empty():
    mock_crt = AsyncMock()
    mock_crt.fetch_subdomains.return_value = []
    resolver = ScopePatternResolver(crt_client=mock_crt)
    res = await resolver.resolve_scope("prod-*.example.com")

    assert res == ["example.com"]
