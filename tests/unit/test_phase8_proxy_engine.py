import pytest
from penflow.traffic.proxy_engine import ProxyConfig
from penflow.traffic.http_client import StatefulHttpClient
from penflow.capabilities.execution_context import CapabilityExecutionContext
from penflow.knowledge.knowledge_store import KnowledgeStore

def test_proxy_config_dict_generation():
    cfg = ProxyConfig(http_proxy="http://127.0.0.1:8080")
    d = cfg.get_proxies_dict()
    assert d["http://"] == "http://127.0.0.1:8080"
    assert d["https://"] == "http://127.0.0.1:8080"

def test_execution_context_proxy_integration():
    cfg = ProxyConfig(http_proxy="http://127.0.0.1:8080")
    ks = KnowledgeStore()
    ctx = CapabilityExecutionContext(asset="target.com", knowledge_store=ks, proxy_config=cfg)

    client = ctx.get_http_client()
    assert client.proxy_config is not None
    assert client.proxy_config.http_proxy == "http://127.0.0.1:8080"
