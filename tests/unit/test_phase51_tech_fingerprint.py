import pytest
from penflow.recon.tech_fingerprint import TechnologyFingerprintEngine

def test_spring_boot_detection():
    engine = TechnologyFingerprintEngine()
    analysis = engine.analyze_response_signatures(
        headers={"Content-Type": "text/html"},
        body_text="<html><body><h1>Whitelabel Error Page</h1><p>This application has no explicit mapping for /error</p></body></html>"
    )
    assert analysis["framework"] == "SpringBoot"
    assert "Framework:SpringBoot" in analysis["technologies"]
    assert "polyglot_ssti" in analysis["recommended_agents"]

def test_abp_framework_detection():
    engine = TechnologyFingerprintEngine()
    analysis = engine.analyze_response_signatures(
        headers={},
        body_text="<script src='/abp/abp.js'></script><script>abp.localization.values = {};</script>"
    )
    assert analysis["framework"] == "ABP_Boilerplate"
    assert "Framework:ABP_Boilerplate" in analysis["technologies"]
    assert "bfla" in analysis["recommended_agents"]
    assert "idor" in analysis["recommended_agents"]

def test_llm_frontend_detection():
    engine = TechnologyFingerprintEngine()
    analysis = engine.analyze_response_signatures(
        headers={},
        body_text="<div id='gradio-app'><div class='prompt-input'>Ask AI...</div></div>"
    )
    assert "AI:LLM_Frontend" in analysis["technologies"]
    assert "prompt_injection_audit" in analysis["recommended_agents"]
