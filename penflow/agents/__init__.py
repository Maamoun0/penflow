from penflow.agents.capability_agent import BaseCapabilityAgent
from penflow.agents.idor_agent import IDORCapabilityAgent
from penflow.agents.bfla_agent import BFLACapabilityAgent
from penflow.agents.mass_assignment_agent import MassAssignmentCapabilityAgent
from penflow.agents.graphql_agent import GraphQLCapabilityAgent
from penflow.agents.race_condition_agent import RaceConditionCapabilityAgent
from penflow.agents.oauth_jwt_agent import OAuthJWTCapabilityAgent
from penflow.agents.cors_agent import CORSCapabilityAgent
from penflow.agents.ssrf_agent import SSRFCapabilityAgent
from penflow.agents.nosql_sqli_agent import NoSQLSQLiCapabilityAgent
from penflow.agents.ssti_rce_agent import SSTIRCECapabilityAgent
from penflow.agents.info_disclosure_agent import InfoDisclosureCapabilityAgent
from penflow.agents.rate_limit_agent import RateLimitCapabilityAgent
from penflow.agents.open_redirect_agent import OpenRedirectCapabilityAgent
from penflow.agents.security_config_agent import SecurityConfigCapabilityAgent
from penflow.agents.xss_agent import XSSCapabilityAgent
from penflow.agents.http_smuggling_agent import HTTPSmugglingCapabilityAgent
from penflow.agents.subdomain_takeover_agent import SubdomainTakeoverCapabilityAgent
from penflow.agents.parameter_discovery_agent import ParameterDiscoveryCapabilityAgent
from penflow.agents.cache_poisoning_agent import WebCachePoisoningCapabilityAgent
from penflow.agents.prototype_pollution_agent import PrototypePollutionCapabilityAgent
from penflow.agents.business_logic_agent import BusinessLogicCapabilityAgent
from penflow.agents.xxe_agent import XXECapabilityAgent
from penflow.agents.account_takeover_agent import AccountTakeoverCapabilityAgent
from penflow.agents.unicode_normalization_agent import UnicodeNormalizationAgent
from penflow.agents.parser_differential_agent import ParserDifferentialAgent
from penflow.agents.orm_leak_agent import ORMLeakAgent
from penflow.agents.novel_ssrf_redirect_agent import NovelSSRFRedirectAgent
from penflow.agents.xs_leak_agent import XSLeakAgent
from penflow.agents.framework_cache_poisoning_agent import FrameworkCachePoisoningAgent
from penflow.agents.polyglot_ssti_agent import PolyglotSSTIAgent
from penflow.agents.cspt_agent import ClientSidePathTraversalAgent
from penflow.agents.prompt_injection_agent import PromptInjectionAgent
from penflow.agents.ai_agent_security_agent import AIAgentSecurityAgent
from penflow.agents.rag_poisoning_agent import RAGPoisoningDetector

# Phase 2 Agents
from penflow.agents.path_traversal_agent import PathTraversalCapabilityAgent
from penflow.agents.websocket_agent import WebSocketCapabilityAgent
from penflow.agents.cloud_misconfig_agent import CloudMisconfigCapabilityAgent
from penflow.agents.second_order_injection_agent import SecondOrderInjectionAgent
from penflow.agents.api_version_regression_agent import APIVersionRegressionAgent
from penflow.agents.differential_timing_agent import DifferentialTimingAgent
from penflow.agents.response_clustering_agent import ResponseClusteringAgent
from penflow.agents.crlf_injection_agent import CRLFInjectionAgent
from penflow.agents.header_analysis_agent import HeaderAnalysisAgent
from penflow.agents.sqli_agent import SQLiCapabilityAgent
from penflow.agents.nosql_injection_agent import NoSQLInjectionAgent

# Phase 3 Advanced 2025/2026 Attack Vector Agents
from penflow.agents.saml_bypass_agent import SAMLBypassCapabilityAgent
from penflow.agents.http2_connect_agent import HTTP2ConnectCapabilityAgent
from penflow.agents.multipart_parser_bypass_agent import MultipartParserBypassCapabilityAgent
from penflow.agents.cl0_smuggling_agent import CL0SmugglingCapabilityAgent
from penflow.agents.pdo_sqli_agent import PDOSQLiAgent
from penflow.agents.double_clickjacking_agent import DoubleClickjackingAgent
from penflow.agents.mcp_server_agent import MCPServerAgent
from penflow.agents.ai_supply_chain_agent import AISupplyChainAgent
from penflow.agents.webauthn_bypass_agent import WebAuthnBypassCapabilityAgent

__all__ = [
    "BaseCapabilityAgent",
    "IDORCapabilityAgent",
    "BFLACapabilityAgent",
    "MassAssignmentCapabilityAgent",
    "GraphQLCapabilityAgent",
    "RaceConditionCapabilityAgent",
    "OAuthJWTCapabilityAgent",
    "CORSCapabilityAgent",
    "SSRFCapabilityAgent",
    "NoSQLSQLiCapabilityAgent",
    "SSTIRCECapabilityAgent",
    "InfoDisclosureCapabilityAgent",
    "RateLimitCapabilityAgent",
    "OpenRedirectCapabilityAgent",
    "SecurityConfigCapabilityAgent",
    "XSSCapabilityAgent",
    "HTTPSmugglingCapabilityAgent",
    "SubdomainTakeoverCapabilityAgent",
    "ParameterDiscoveryCapabilityAgent",
    "WebCachePoisoningCapabilityAgent",
    "PrototypePollutionCapabilityAgent",
    "BusinessLogicCapabilityAgent",
    "XXECapabilityAgent",
    "AccountTakeoverCapabilityAgent",
    "UnicodeNormalizationAgent",
    "ParserDifferentialAgent",
    "ORMLeakAgent",
    "NovelSSRFRedirectAgent",
    "XSLeakAgent",
    "FrameworkCachePoisoningAgent",
    "PolyglotSSTIAgent",
    "ClientSidePathTraversalAgent",
    "PromptInjectionAgent",
    "AIAgentSecurityAgent",
    "RAGPoisoningDetector",
    "PathTraversalCapabilityAgent",
    "WebSocketCapabilityAgent",
    "CloudMisconfigCapabilityAgent",
    "SecondOrderInjectionAgent",
    "APIVersionRegressionAgent",
    "DifferentialTimingAgent",
    "ResponseClusteringAgent",
    "CRLFInjectionAgent",
    "HeaderAnalysisAgent",
    "SQLiCapabilityAgent",
    "NoSQLInjectionAgent",

    # Phase 3 Agents
    "SAMLBypassCapabilityAgent",
    "HTTP2ConnectCapabilityAgent",
    "MultipartParserBypassCapabilityAgent",
    "CL0SmugglingCapabilityAgent",
    "PDOSQLiAgent",
    "DoubleClickjackingAgent",
    "MCPServerAgent",
    "AISupplyChainAgent",
    "WebAuthnBypassCapabilityAgent",
]
