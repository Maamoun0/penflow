import pytest
from penflow.infrastructure.waf_evasion import (
    WAFTypeDetector,
    WAFVendor,
    AdaptivePayloadEncoder,
    WAFBypassCoordinator
)

def test_waf_detection():
    # Cloudflare check
    cf = WAFTypeDetector.detect_waf(headers={"server": "cloudflare", "cf-ray": "12345"}, cookies={})
    assert cf == WAFVendor.CLOUDFLARE

    # Akamai check
    ak = WAFTypeDetector.detect_waf(headers={"x-akamai-transformed": "9"}, cookies={"ak_bmsc": "xyz"})
    assert ak == WAFVendor.AKAMAI

    # AWS WAF check
    aws = WAFTypeDetector.detect_waf(headers={"x-amzn-requestid": "abc-123"}, cookies={})
    assert aws == WAFVendor.AWS_WAF

    # Unknown
    unk = WAFTypeDetector.detect_waf(headers={}, cookies={})
    assert unk == WAFVendor.UNKNOWN

def test_payload_encoders():
    encoder = AdaptivePayloadEncoder()

    # Double URL encode
    raw = "' OR 1=1--"
    d_enc = encoder.double_url_encode(raw)
    assert "%2527" in d_enc

    # Unicode fullwidth
    fw = encoder.unicode_fullwidth_transform("admin")
    assert fw != "admin"
    assert ord(fw[0]) > 0xF000

    # SQL comment interleaving
    sql = "SELECT * FROM users WHERE id=1 UNION SELECT name FROM admin"
    inter = encoder.sql_comment_interleave(sql)
    assert "SE/**/LECT" in inter
    assert "UN/**/ION" in inter

    # Alternating case
    alt = encoder.mutate_case_alternation("select")
    assert alt == "SeLeCt"

def test_waf_bypass_coordinator():
    coord = WAFBypassCoordinator()
    variants = coord.generate_evasion_variants("UNION SELECT 1,2,3", WAFVendor.CLOUDFLARE)
    assert len(variants) >= 5
    techs = [v["technique"] for v in variants]
    assert "double_url_encode" in techs
    assert "unicode_fullwidth" in techs
