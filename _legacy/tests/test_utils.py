from penflow.utils.url_utils import (
    normalize_url,
    extract_domain,
    is_same_origin,
    is_static_resource,
    classify_endpoint
)

def test_normalize_url():
    assert normalize_url("HTTP://EXAMPLE.COM/path?b=2&a=1#frag") == "http://example.com/path?a=1&b=2"
    assert normalize_url("https://example.com") == "https://example.com/"

def test_extract_domain():
    assert extract_domain("https://sub.example.com:8080/path") == "sub.example.com"
    assert extract_domain("invalid-url") == ""

def test_is_same_origin():
    assert is_same_origin("https://example.com/page1", "https://example.com/page2") is True
    assert is_same_origin("https://example.com", "http://example.com") is False

def test_is_static_resource():
    assert is_static_resource("https://example.com/logo.png") is True
    assert is_static_resource("https://example.com/index.html") is False
    assert is_static_resource("https://example.com/static/style.css?v=2") is True

def test_classify_endpoint():
    assert classify_endpoint("https://example.com/api/v1/users") == "api"
    assert classify_endpoint("https://example.com/admin/login") == "admin"
    assert classify_endpoint("https://example.com/login") == "auth"
    assert classify_endpoint("https://example.com/graphql") == "graphql"
    assert classify_endpoint("https://example.com/logo.png") == "static"
    assert classify_endpoint("https://example.com/about") == "page"
