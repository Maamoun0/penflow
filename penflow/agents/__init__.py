"""
PenFlow Agents Package.
Exposes base agent interfaces and auto-discovery utilities across all domain packages.
"""
from penflow.agents.base.base_agent import BaseAgent, BaseSwarmAgent
from penflow.agents.base.capability_agent import BaseCapabilityAgent
from penflow.agents.base.registry_loader import RegistryLoader, register_agent

from penflow.agents.authz import IDORCapabilityAgent, BFLACapabilityAgent, MassAssignmentCapabilityAgent, AccountTakeoverCapabilityAgent
from penflow.agents.injection import (
    XSSCapabilityAgent, SQLiCapabilityAgent, NoSQLInjectionAgent, NoSQLSQLiCapabilityAgent,
    PDOSQLiAgent, PolyglotSSTIAgent, SSTIRCECapabilityAgent, XXECapabilityAgent,
    ORMLeakAgent, CRLFInjectionAgent, PrototypePollutionCapabilityAgent, SecondOrderInjectionAgent
)
from penflow.agents.protocol import (
    HTTPSmugglingCapabilityAgent, CL0SmugglingCapabilityAgent, HTTP2ConnectCapabilityAgent,
    WebSocketCapabilityAgent, CORSCapabilityAgent, WebCachePoisoningCapabilityAgent,
    FrameworkCachePoisoningAgent, MultipartParserBypassCapabilityAgent
)
from penflow.agents.auth import OAuthJWTCapabilityAgent, SAMLBypassCapabilityAgent, WebAuthnBypassCapabilityAgent, RateLimitCapabilityAgent
from penflow.agents.ssrf import SSRFCapabilityAgent, NovelSSRFRedirectAgent, CloudMisconfigCapabilityAgent
from penflow.agents.recon import (
    SubdomainTakeoverCapabilityAgent, HeaderAnalysisAgent, InfoDisclosureCapabilityAgent,
    ParameterDiscoveryCapabilityAgent, ResponseClusteringAgent, DifferentialTimingAgent,
    SecurityConfigCapabilityAgent, GraphQLCapabilityAgent, OpenRedirectCapabilityAgent,
    RaceConditionCapabilityAgent, BusinessLogicCapabilityAgent
)
from penflow.agents.ai import PromptInjectionAgent, RAGPoisoningDetector, AIAgentSecurityAgent, AISupplyChainAgent
from penflow.agents.modern import (
    ClientSidePathTraversalAgent, XSLeakAgent, ParserDifferentialAgent, MCPServerAgent,
    MCPServerAttackAgent, DoubleClickjackingAgent, PathTraversalCapabilityAgent,
    UnicodeNormalizationAgent, APIVersionRegressionAgent
)

__all__ = [
    "BaseAgent",
    "BaseSwarmAgent",
    "BaseCapabilityAgent",
    "RegistryLoader",
    "register_agent",
    "IDORCapabilityAgent",
    "BFLACapabilityAgent",
    "MassAssignmentCapabilityAgent",
    "AccountTakeoverCapabilityAgent",
    "XSSCapabilityAgent",
    "SQLiCapabilityAgent",
    "NoSQLInjectionAgent",
    "NoSQLSQLiCapabilityAgent",
    "PDOSQLiAgent",
    "PolyglotSSTIAgent",
    "SSTIRCECapabilityAgent",
    "XXECapabilityAgent",
    "ORMLeakAgent",
    "CRLFInjectionAgent",
    "PrototypePollutionCapabilityAgent",
    "SecondOrderInjectionAgent",
    "HTTPSmugglingCapabilityAgent",
    "CL0SmugglingCapabilityAgent",
    "HTTP2ConnectCapabilityAgent",
    "WebSocketCapabilityAgent",
    "CORSCapabilityAgent",
    "WebCachePoisoningCapabilityAgent",
    "FrameworkCachePoisoningAgent",
    "MultipartParserBypassCapabilityAgent",
    "OAuthJWTCapabilityAgent",
    "AMLBypassCapabilityAgent",
    "WebAuthnBypassCapabilityAgent",
    "RateLimitCapabilityAgent",
    "SSRFCapabilityAgent",
    "NovelSSRFRedirectAgent",
    "CloudMisconfigCapabilityAgent",
    "SubdomainTakeoverCapabilityAgent",
    "HeaderAnalysisAgent",
    "InfoDisclosureCapabilityAgent",
    "ParameterDiscoveryCapabilityAgent",
    "ResponseClusteringAgent",
    "DifferentialTimingAgent",
    "SecurityConfigCapabilityAgent",
    "GraphQLCapabilityAgent",
    "OpenRedirectCapabilityAgent",
    "RaceConditionCapabilityAgent",
    "BusinessLogicCapabilityAgent",
    "PromptInjectionAgent",
    "RAGPoisoningDetector",
    "AIAgentSecurityAgent",
    "AISupplyChainAgent",
    "ClientSidePathTraversalAgent",
    "XSLeakAgent",
    "ParserDifferentialAgent",
    "MCPServerAgent",
    "MCPServerAttackAgent",
    "DoubleClickjackingAgent",
    "PathTraversalCapabilityAgent",
    "UnicodeNormalizationAgent",
    "APIVersionRegressionAgent"
]
