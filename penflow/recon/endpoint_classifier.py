"""
EndpointClassifier: Dynamically classifies discovered endpoints by vulnerability type
and maps them to the appropriate Capability Agents.

Analyzes crawl results, tech fingerprints, and form data to produce typed endpoint
records that agents can act on directly, eliminating hardcoded fallback URLs.
"""
from typing import List, Dict, Any, Set
from urllib.parse import urlparse, parse_qs
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.recon.endpoint_classifier")

# Patterns that indicate specific API/technology types
GRAPHQL_INDICATORS = {"graphql", "gql", "/graphiql", "/playground", "/altair"}
REST_API_INDICATORS = {"/api/", "/v1/", "/v2/", "/v3/", "/rest/", "/json/"}
WEBSOCKET_INDICATORS = {"ws://", "wss://", "/ws", "/socket", "/realtime", "/cable"}
AUTH_INDICATORS = {"/oauth", "/auth", "/login", "/token", "/sso", "/saml", "/callback", "/jwt"}
UPLOAD_INDICATORS = {"/upload", "/import", "/attach", "/media"}
ADMIN_INDICATORS = {"/admin", "/dashboard", "/manage", "/internal", "/console", "/panel"}

# Parameters that suggest IDOR/BOLA vulnerability surface
IDOR_PARAM_PATTERNS = {"id", "uid", "user_id", "userId", "account_id", "accountId",
                        "order_id", "orderId", "doc_id", "docId", "profile_id",
                        "item_id", "itemId", "record_id", "recordId", "ref",
                        "invoice", "ticket", "report_id", "file_id", "comment_id"}

# Content types that indicate API endpoints
API_CONTENT_TYPES = {"application/json", "application/graphql", "application/xml"}


class ClassifiedEndpoint:
    """A single endpoint with classification metadata."""
    def __init__(self, url: str, endpoint_type: str, method: str = "GET",
                 parameters: List[str] = None, confidence: float = 0.5,
                 tags: List[str] = None, source: str = "crawler"):
        self.url = url
        self.endpoint_type = endpoint_type  # rest_api, graphql, auth, admin, form, websocket, static
        self.method = method
        self.parameters = parameters or []
        self.confidence = confidence
        self.tags = tags or []
        self.source = source

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "type": self.endpoint_type,
            "method": self.method,
            "parameters": self.parameters,
            "confidence": self.confidence,
            "tags": self.tags,
            "source": self.source
        }


class EndpointClassifier:
    """
    Classifies discovered endpoints by analyzing URL patterns, parameters,
    content types, and technology fingerprints to determine which Capability Agents
    should test each endpoint.
    """

    def classify_from_crawl(self, crawl_data: Dict[str, Any]) -> List[ClassifiedEndpoint]:
        """Classify endpoints from SmartCrawler results."""
        classified: List[ClassifiedEndpoint] = []

        # Process discovered endpoints
        endpoints = crawl_data.get("endpoints", [])
        for ep in endpoints:
            url = ep.get("url", "")
            content_type = ep.get("content_type", "")
            status = ep.get("status", 0)

            if not url or status >= 400:
                continue

            # Skip static assets
            parsed = urlparse(url)
            path_lower = parsed.path.lower()
            if any(path_lower.endswith(ext) for ext in
                   [".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
                    ".ico", ".woff", ".woff2", ".ttf", ".map"]):
                continue

            endpoint_type, tags, confidence = self._classify_url(url, content_type)
            classified.append(ClassifiedEndpoint(
                url=url, endpoint_type=endpoint_type,
                method="GET", confidence=confidence, tags=tags,
                source="crawler"
            ))

        # Process discovered forms (these have POST methods and parameters)
        forms = crawl_data.get("forms", [])
        for form in forms:
            action = form.get("action", "")
            method = form.get("method", "POST").upper()
            params = form.get("parameters", [])

            if not action:
                continue

            tags = ["form_endpoint"]
            confidence = 0.6

            # Check for mass assignment surface
            if len(params) >= 3:
                tags.append("mass_assignment_candidate")
                confidence = 0.75

            # Check for auth forms
            auth_params = {"password", "passwd", "pass", "username", "email", "login"}
            if any(p.lower() in auth_params for p in params):
                tags.append("authentication_form")

            classified.append(ClassifiedEndpoint(
                url=action, endpoint_type="form",
                method=method, parameters=params,
                confidence=confidence, tags=tags,
                source="crawler_form"
            ))

        logger.info(f"[EndpointClassifier] Classified {len(classified)} endpoints from crawl data.")
        return classified

    def classify_from_tech(self, tech_data: Dict[str, Any]) -> List[str]:
        """
        Extract technology tags that influence which agents to prioritize.
        Returns a list of tech-based hint tags.
        """
        hints: List[str] = []
        technologies = tech_data.get("technologies", [])
        headers = tech_data.get("detected_headers", {})

        for tech in technologies:
            tech_lower = tech.lower() if isinstance(tech, str) else ""
            if "graphql" in tech_lower:
                hints.append("graphql_detected")
            if "jwt" in tech_lower or "bearer" in tech_lower:
                hints.append("jwt_detected")
            if "oauth" in tech_lower:
                hints.append("oauth_detected")
            if "websocket" in tech_lower:
                hints.append("websocket_detected")
            if "cors" in tech_lower:
                hints.append("cors_relevant")

        # Check security headers
        if isinstance(headers, dict):
            if "access-control-allow-origin" in {k.lower() for k in headers.keys()}:
                hints.append("cors_relevant")
            if "authorization" in {k.lower() for k in headers.keys()}:
                hints.append("auth_header_present")

        logger.info(f"[EndpointClassifier] Tech hints: {hints}")
        return hints

    def get_agent_mapping(self, classified_endpoints: List[ClassifiedEndpoint],
                          tech_hints: List[str] = None) -> Dict[str, List[Dict[str, Any]]]:
        """
        Map classified endpoints to the capability IDs that should test them.
        Returns {capability_id: [endpoint_dicts]}.
        """
        tech_hints = tech_hints or []
        mapping: Dict[str, List[Dict[str, Any]]] = {}

        for ep in classified_endpoints:
            target_caps = self._get_capabilities_for_endpoint(ep, tech_hints)
            for cap_id in target_caps:
                if cap_id not in mapping:
                    mapping[cap_id] = []
                mapping[cap_id].append(ep.to_dict())

        logger.info(f"[EndpointClassifier] Agent mapping: { {k: len(v) for k, v in mapping.items()} }")
        return mapping

    def _classify_url(self, url: str, content_type: str = "") -> tuple:
        """Classify a single URL. Returns (endpoint_type, tags, confidence)."""
        parsed = urlparse(url)
        path_lower = parsed.path.lower()
        query_params = parse_qs(parsed.query)
        tags: List[str] = []
        confidence = 0.5

        # GraphQL detection
        if any(ind in path_lower for ind in GRAPHQL_INDICATORS):
            tags.append("graphql")
            return ("graphql", tags, 0.90)

        # Auth/OAuth endpoint
        if any(ind in path_lower for ind in AUTH_INDICATORS):
            tags.append("authentication")
            return ("auth", tags, 0.80)

        # Admin panel
        if any(ind in path_lower for ind in ADMIN_INDICATORS):
            tags.append("admin_panel")
            return ("admin", tags, 0.75)

        # REST API
        if any(ind in path_lower for ind in REST_API_INDICATORS):
            tags.append("rest_api")
            # Check for IDOR-susceptible parameters
            for param_name in query_params.keys():
                if param_name.lower() in IDOR_PARAM_PATTERNS:
                    tags.append("idor_candidate")
                    confidence = 0.85
                    break
            return ("rest_api", tags, max(confidence, 0.70))

        # API-like content type
        if any(ct in content_type.lower() for ct in API_CONTENT_TYPES):
            tags.append("api_response")
            return ("rest_api", tags, 0.65)

        # Check for ID parameters in non-API URLs (still IDOR surface)
        for param_name in query_params.keys():
            if param_name.lower() in IDOR_PARAM_PATTERNS:
                tags.append("idor_candidate")
                return ("parameterized", tags, 0.70)

        return ("page", tags, 0.40)

    def _get_capabilities_for_endpoint(self, ep: ClassifiedEndpoint,
                                        tech_hints: List[str]) -> List[str]:
        """Determine which capability IDs should test this endpoint."""
        caps: Set[str] = set()

        # Type-based mapping
        if ep.endpoint_type == "graphql" or "graphql" in ep.tags:
            caps.add("graphql_introspection")
            caps.add("graphql_depth_analysis")

        if "idor_candidate" in ep.tags or ep.endpoint_type in ("rest_api", "parameterized"):
            caps.add("id_access_analysis")
            caps.add("authorization")
            caps.add("bola_check")

        if ep.endpoint_type == "auth" or "authentication" in ep.tags:
            caps.add("oauth_misconfiguration")
            caps.add("jwt_validation")

        if ep.endpoint_type == "form" or "mass_assignment_candidate" in ep.tags:
            caps.add("mass_assignment_analysis")

        if ep.endpoint_type == "admin" or ep.endpoint_type == "rest_api":
            caps.add("bfla_analysis")

        # SSRF: any URL parameter or redirect parameter
        parsed = urlparse(ep.url)
        params = parse_qs(parsed.query)
        path_lower = parsed.path.lower()

        ssrf_params = {"url", "uri", "fetch", "proxy", "host", "target", "feed", "link", "image"}
        redirect_params = {"redirect", "next", "return", "dest", "callback", "redir", "return_url", "redirect_uri", "goto", "out"}

        if any(p.lower() in ssrf_params for p in params.keys()):
            caps.add("ssrf_metadata_exfiltration")
            caps.add("ssrf_analysis")

        if any(p.lower() in redirect_params for p in params.keys()):
            caps.add("open_redirect")

        # XSS: parameter query or form endpoints
        if params or ep.endpoint_type in ("parameterized", "form", "rest_api"):
            caps.add("reflected_xss")
            if ep.endpoint_type == "form" or ep.method == "POST":
                caps.add("stored_xss")

        # Parameter Discovery: run on all endpoints
        caps.add("parameter_discovery")

        # HTTP Request Smuggling: API & proxy paths
        if ep.endpoint_type in ("rest_api", "admin", "auth") or any(k in path_lower for k in ["/api/", "/v1/", "/v2/"]):
            caps.add("http_smuggling_desync")

        # Subdomain Takeover: pages and subdomains
        caps.add("subdomain_takeover_check")

        # SQLi & NoSQLi: any search, filter, sort, id, or query params
        sql_nosql_params = {"q", "query", "search", "filter", "sort", "order", "id", "user", "username", "name", "email", "category"}
        if any(p.lower() in sql_nosql_params for p in params.keys()) or ep.endpoint_type in ("rest_api", "parameterized"):
            caps.add("sql_injection")
            caps.add("nosql_injection")

        # SSTI: dynamic template or preview rendering endpoints
        ssti_keywords = {"render", "template", "preview", "email", "view", "print", "display", "generate"}
        if any(kw in path_lower for kw in ssti_keywords) or any(p.lower() in {"template", "text", "msg", "content", "render"} for p in params.keys()):
            caps.add("ssti_analysis")

        # Command Injection / RCE: ping, diagnostic, exec, convert, image processing endpoints
        rce_keywords = {"exec", "command", "ping", "diag", "test", "convert", "process", "shell", "run", "pdf"}
        if any(kw in path_lower for kw in rce_keywords) or any(p.lower() in {"cmd", "exec", "command", "file", "path", "ip", "host"} for p in params.keys()):
            caps.add("command_injection")

        # Rate Limit bypass: auth, login, OTP, reset, checkout, sensitive endpoints
        auth_rate_keywords = {"login", "signin", "auth", "token", "otp", "verify", "reset", "forgot", "register", "signup"}
        if any(kw in path_lower for kw in auth_rate_keywords) or ep.endpoint_type == "auth":
            caps.add("rate_limit_bypass")

        # Info Disclosure: debug, actuator, docs, metrics endpoints
        debug_keywords = {"actuator", "swagger", "api-docs", "openapi", "metrics", "health", "debug", "env"}
        if any(kw in path_lower for kw in debug_keywords):
            caps.add("info_disclosure")

        # Tech hints enrichment
        if "cors_relevant" in tech_hints and ep.endpoint_type in ("rest_api", "auth"):
            caps.add("cors_misconfiguration")

        if "jwt_detected" in tech_hints and ep.endpoint_type in ("rest_api", "auth"):
            caps.add("jwt_validation")

        if "oauth_detected" in tech_hints:
            caps.add("oauth_misconfiguration")

        if "websocket_detected" in tech_hints or ep.endpoint_type == "websocket":
            caps.add("websocket_auth_flaw")

        # Race conditions: forms with POST + financial/state-changing context
        if ep.method == "POST" and ep.endpoint_type in ("form", "rest_api"):
            race_keywords = {"checkout", "transfer", "purchase", "redeem",
                             "coupon", "vote", "like", "follow", "withdraw",
                             "payment", "order", "subscribe"}
            if any(kw in path_lower for kw in race_keywords):
                caps.add("race_condition_analysis")

        return list(caps)
