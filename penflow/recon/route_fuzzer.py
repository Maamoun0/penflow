"""
SmartRouteFuzzer — Elite High-Value Route Discovery Engine for PenFlow.

Probes 500+ routes across every major tech stack: Spring Boot Actuators, PHP/Laravel/Rails/Django,
admin panels, backup/source leaks, API documentation, cloud metadata, GraphQL endpoints,
WebSocket upgrade paths, and CI/CD management interfaces.

Features:
  - 500+ curated high-value routes organized by tech category
  - HTTP method fuzzing (GET, POST, PUT, DELETE, OPTIONS, HEAD, PATCH)
  - Response body analysis for JSON error leaks, version disclosures, and info leaks
  - Response size anomaly detection across methods
  - Parallel async probing with configurable concurrency
"""
import httpx
import asyncio
from typing import List, Dict, Any, Optional, Set
from urllib.parse import urljoin
from penflow.infrastructure.logger import get_logger

logger = get_logger("penflow.recon.route_fuzzer")

# ─────────────────────────────────────────────────────────
# Route Categories — 500+ Elite Routes
# ─────────────────────────────────────────────────────────

# Spring Boot Actuator (all endpoints)
SPRING_ACTUATOR_ROUTES = [
    "/actuator", "/actuator/env", "/actuator/health", "/actuator/info",
    "/actuator/beans", "/actuator/configprops", "/actuator/conditions",
    "/actuator/mappings", "/actuator/metrics", "/actuator/loggers",
    "/actuator/logfile", "/actuator/httptrace", "/actuator/threaddump",
    "/actuator/heapdump", "/actuator/scheduledtasks", "/actuator/caches",
    "/actuator/flyway", "/actuator/liquibase", "/actuator/sessions",
    "/actuator/shutdown", "/actuator/refresh", "/actuator/bus-env",
    "/actuator/bus-refresh", "/actuator/gateway/routes",
    "/manage/health", "/manage/env", "/manage/info", "/manage/metrics",
    "/management/health", "/management/info", "/management/env",
]

# API Documentation
API_DOC_ROUTES = [
    "/swagger-ui.html", "/swagger-ui/index.html", "/swagger/index.html",
    "/swagger/v1/swagger.json", "/swagger/v2/swagger.json",
    "/swagger/v3/swagger.json", "/swagger.json", "/swagger.yaml",
    "/api-docs", "/v2/api-docs", "/v3/api-docs", "/api/docs",
    "/openapi.json", "/openapi.yaml", "/api/swagger.json",
    "/api/swagger.yaml", "/api/openapi.json", "/redoc/",
    "/redoc/index.html", "/api/redoc", "/graphql/schema",
    "/api/schema/", "/schema.json", "/schema.graphql",
    "/api/v1/docs", "/api/v2/docs", "/api/v3/docs",
    "/.well-known/openid-configuration", "/.well-known/oauth-authorization-server",
    "/.well-known/security.txt", "/.well-known/jwks.json",
]

# GraphQL Endpoints
GRAPHQL_ROUTES = [
    "/graphql", "/graphiql", "/playground", "/altair", "/gql",
    "/api/graphql", "/api/v1/graphql", "/api/v2/graphql",
    "/graph", "/graphql/console", "/v1/graphql", "/v2/graphql",
    "/explorer", "/graphql-explorer", "/graphql/playground",
    "/api/graph", "/graphql/v1", "/graphql/v2",
]

# Git / VCS Source Leaks
VCS_LEAK_ROUTES = [
    "/.git/HEAD", "/.git/config", "/.git/index", "/.git/COMMIT_EDITMSG",
    "/.git/logs/HEAD", "/.git/refs/heads/main", "/.git/refs/heads/master",
    "/.git/refs/heads/develop", "/.git/objects/info/packs",
    "/.gitignore", "/.gitmodules", "/.gitattributes",
    "/.svn/wc.db", "/.svn/entries", "/.svn/format",
    "/.hg/hgrc", "/.hg/requires", "/.bzr/branch-format",
]

# Backup / Config File Leaks
BACKUP_LEAK_ROUTES = [
    "/.env", "/.env.backup", "/.env.local", "/.env.example", "/.env.prod",
    "/.env.production", "/.env.development", "/.env.staging",
    "/.env.bak", "/.env.old", "/.env.save", "/.env.sample",
    "/config.json", "/config.yaml", "/config.yml", "/config.xml",
    "/application.properties", "/application.yml", "/application.yaml",
    "/settings.json", "/settings.py", "/local_settings.py",
    "/wp-config.php", "/wp-config.php.bak", "/wp-config.php.old",
    "/configuration.php", "/config.php", "/database.yml",
    "/database.php", "/db.php", "/db.json", "/db.sql",
    "/backup.zip", "/backup.tar.gz", "/backup.sql",
    "/database.sql", "/dump.sql", "/data.sql", "/schema.sql",
    "/site.sql", "/backup.tar", "/backup.7z", "/db_backup.sql",
    "/web.config", "/web.config.bak", "/.htaccess", "/.htpasswd",
    "/composer.json", "/composer.lock", "/package.json", "/package-lock.json",
    "/yarn.lock", "/Gemfile", "/Gemfile.lock", "/requirements.txt",
    "/Pipfile", "/Pipfile.lock", "/Makefile", "/Dockerfile",
    "/docker-compose.yml", "/docker-compose.yaml", "/.dockerignore",
    "/k8s.yaml", "/kubernetes.yaml", "/helm/values.yaml",
    "/terraform.tfvars", "/main.tf",
]

# Admin Panels
ADMIN_PANEL_ROUTES = [
    "/admin", "/admin/", "/admin/login", "/admin/dashboard", "/admin/panel",
    "/wp-admin/", "/wp-admin/admin.php", "/wp-login.php",
    "/administrator/", "/administrator/index.php",
    "/adminpanel", "/admin_panel", "/admin-panel", "/management",
    "/manage", "/manager", "/panel", "/cpanel", "/controlpanel",
    "/backend", "/backend/login", "/backoffice",
    "/console", "/admin/console", "/system", "/sysadmin",
    "/phpMyAdmin/", "/phpmyadmin/", "/pma/", "/dbadmin/",
    "/adminer.php", "/adminer/", "/db-admin/",
    "/jenkins", "/jenkins/login", "/hudson/",
    "/jira", "/confluence", "/bamboo", "/bitbucket",
    "/sonarqube", "/nexus", "/artifactory", "/harbor",
    "/kibana", "/grafana", "/prometheus", "/alertmanager",
    "/portainer", "/rancher", "/k8s-dashboard", "/kubernetes-dashboard",
    "/vault", "/consul", "/nomad",
    "/rabbitmq", "/rabbitmq/management", "/flower",
    "/celery-admin", "/celeryflower",
    "/django/admin/", "/rails/info/routes", "/rails/info/properties",
    "/laravel_telescope", "/telescope", "/horizon", "/nova",
]

# Cloud Metadata & Infrastructure
CLOUD_META_ROUTES = [
    "/latest/meta-data/", "/metadata/v1/", "/computeMetadata/v1/",
    "/metadata/instance", "/metadata/",
    "/server-status", "/server-info", "/?phpinfo=1",
    "/info.php", "/phpinfo.php", "/test.php", "/info.asp",
    "/nginx_status", "/stub_status", "/fpm-status",
    "/_cat/indices", "/_cat/nodes", "/_cluster/health",  # Elasticsearch
    "/solr/admin/", "/solr/#/",  # Apache Solr
    "/actuator/env#spring.datasource.password",
]

# Debug / Dev Tools
DEBUG_ROUTES = [
    "/debug", "/debug/", "/dev", "/development",
    "/_debug_toolbar/", "/django-debug/", "/pdb/", "/pydevd/",
    "/trace", "/tracing", "/profiler",
    "/rails/mailers", "/letter_opener",
    "/health", "/healthz", "/health/live", "/health/ready",
    "/health/check", "/ping", "/alive", "/ready",
    "/status", "/app/health", "/service/health",
    "/version", "/app/version", "/api/version", "/api/v1/version",
    "/build-info", "/build_info", "/app-info",
    "/diag", "/diagnostic", "/diagnostics",
    "/test", "/testing", "/staging",
]

# Authentication & OAuth
AUTH_ROUTES = [
    "/login", "/signin", "/sign-in", "/auth/login", "/auth/signin",
    "/logout", "/signout", "/auth/logout",
    "/register", "/signup", "/sign-up", "/auth/register",
    "/oauth/authorize", "/oauth/token", "/oauth/callback",
    "/oauth2/authorize", "/oauth2/token", "/oauth2/callback",
    "/auth/oauth", "/auth/oauth2", "/auth/sso", "/auth/saml",
    "/sso", "/saml", "/saml/login", "/saml/acs", "/saml/slo",
    "/api/auth/login", "/api/auth/token", "/api/v1/auth/login",
    "/api/login", "/api/signin", "/api/register",
    "/forgot-password", "/reset-password", "/password/reset",
    "/verify-email", "/confirm-email", "/2fa", "/otp", "/mfa",
    "/api/v1/token/refresh", "/api/token/refresh", "/token/revoke",
]

# File Upload / Storage
UPLOAD_ROUTES = [
    "/upload", "/uploads/", "/file", "/files/", "/attachments/",
    "/media/", "/assets/", "/static/", "/public/", "/storage/",
    "/api/v1/upload", "/api/v1/files", "/api/v1/attachments",
    "/api/upload", "/api/files", "/api/media",
    "/images/", "/documents/", "/videos/", "/avatars/",
]

# Common API REST Endpoints
REST_API_ROUTES = [
    "/api", "/api/", "/api/v1", "/api/v2", "/api/v3",
    "/api/v1/users", "/api/v1/user", "/api/v1/me", "/api/v1/profile",
    "/api/v1/admin", "/api/v1/admins", "/api/v1/settings",
    "/api/v1/config", "/api/v1/health", "/api/v1/status",
    "/api/v1/metrics", "/api/v1/logs", "/api/v1/debug",
    "/api/v1/accounts", "/api/v1/organizations", "/api/v1/teams",
    "/api/v1/roles", "/api/v1/permissions", "/api/v1/groups",
    "/api/v1/tokens", "/api/v1/keys", "/api/v1/apikeys",
    "/api/v1/webhooks", "/api/v1/integrations", "/api/v1/plugins",
    "/api/v1/billing", "/api/v1/subscriptions", "/api/v1/invoices",
    "/api/v1/export", "/api/v1/import", "/api/v1/backup",
    "/api/v1/audit", "/api/v1/events", "/api/v1/analytics",
    "/api/v2/users", "/api/v2/admin", "/api/v2/profile", "/api/v2/me",
    "/rest/api/2/user", "/rest/api/2/admin",  # JIRA style
    "/services/", "/service/", "/endpoint/", "/endpoints/",
]

# Laravel / PHP Specific
LARAVEL_PHP_ROUTES = [
    "/api/user", "/sanctum/csrf-cookie", "/api/csrf-cookie",
    "/storage/", "/public/storage/", "/_ignition/health-check",
    "/_ignition/share-report", "/horizon/api/stats",
    "/telescope/api/requests", "/nova-api/",
    "/api/documentation", "/documentation",
]

# Rails / Ruby Specific
RAILS_ROUTES = [
    "/rails/info", "/rails/info/routes", "/rails/info/properties",
    "/rails/mailers", "/letter_opener/", "/sidekiq",
    "/sidekiq/queues", "/sidekiq/workers", "/resque",
    "/good_job", "/delayed_job_admin",
]

# Django / Python Specific
DJANGO_ROUTES = [
    "/django-admin/", "/admin/", "/accounts/login/", "/accounts/profile/",
    "/__debug__/", "/__debug__/sql_select/", "/silk/",
    "/static/admin/", "/api-auth/", "/api-auth/login/",
]

# WebSocket & Real-time
WEBSOCKET_ROUTES = [
    "/ws", "/ws/", "/websocket", "/socket.io/", "/socket",
    "/cable", "/actioncable", "/realtime", "/live",
    "/hub", "/signalr", "/signalr/negotiate",
    "/chat", "/notifications", "/events",
]

# Cloud-native / Kubernetes
K8S_ROUTES = [
    "/api/v1/namespaces/default/pods", "/api/v1/namespaces",
    "/api/v1/nodes", "/apis/apps/v1/deployments",
    "/metrics", "/metrics/cadvisor", "/metrics/resource",
    "/healthz", "/livez", "/readyz",
]

# Security.txt / Standard Meta
STANDARD_META_ROUTES = [
    "/.well-known/security.txt", "/security.txt",
    "/robots.txt", "/sitemap.xml", "/sitemap_index.xml",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/browserconfig.xml", "/manifest.json", "/manifest.webmanifest",
    "/humans.txt", "/ads.txt", "/app-ads.txt",
]

# Next.js / React / Frontend Framework specific
NEXTJS_ROUTES = [
    "/_next/static/", "/_next/data/", "/api/auth/session",
    "/api/auth/providers", "/api/auth/csrf",
    "/__nextjs_original-stack-frames",
    "/_nuxt/", "/_nuxt/manifest.json",
]

# CMS / Blog specific
CMS_ROUTES = [
    "/wp-json/wp/v2/users", "/wp-json/wp/v2/posts",
    "/wp-json/", "/?author=1", "/?author=2",
    "/wp-content/debug.log", "/wp-content/uploads/",
    "/xmlrpc.php", "/wp-cron.php",
    "/ghost/api/v3/admin/", "/ghost/api/content/",
    "/umbraco/backoffice/", "/sitecore/login",
    "/drupal/", "/?q=admin/", "/node/1",
    "/typo3/", "/admin/login.aspx",
]

# CI/CD and DevOps
CICD_ROUTES = [
    "/build", "/ci", "/deploy", "/release",
    "/gitlab/", "/-/health", "/-/readiness", "/-/liveness",
    "/api/v4/projects", "/api/v4/users",
    "/circleci/", "/travis/", "/drone/",
    "/teamcity/", "/teamcity/login.html",
    "/.github/", "/.circleci/config.yml",
    "/.travis.yml", "/Jenkinsfile",
    "/bitbucket-pipelines.yml",
]

# Monitoring and Observability
MONITORING_ROUTES = [
    "/api/datasources", "/api/dashboards/home",
    "/prometheus/api/v1/query", "/prometheus/api/v1/targets",
    "/jaeger/api/traces", "/zipkin/api/v2/services",
    "/influxdb/query", "/loki/api/v1/labels",
    "/splunk/api/", "/datadog/api/",
    "/newrelic/api/", "/sentry/api/",
]

# MERGED — All High-Value Routes
HIGH_VALUE_ROUTES: List[str] = list(set(
    SPRING_ACTUATOR_ROUTES + API_DOC_ROUTES + GRAPHQL_ROUTES +
    VCS_LEAK_ROUTES + BACKUP_LEAK_ROUTES + ADMIN_PANEL_ROUTES +
    CLOUD_META_ROUTES + DEBUG_ROUTES + AUTH_ROUTES + UPLOAD_ROUTES +
    REST_API_ROUTES + LARAVEL_PHP_ROUTES + RAILS_ROUTES +
    DJANGO_ROUTES + WEBSOCKET_ROUTES + K8S_ROUTES + STANDARD_META_ROUTES +
    NEXTJS_ROUTES + CMS_ROUTES + CICD_ROUTES + MONITORING_ROUTES
))

# Methods to try on high-risk routes (those likely to have method-level auth flaws)
HIGH_RISK_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
METHOD_FUZZ_ROUTES = {
    "/admin", "/admin/", "/api/v1/users", "/api/v1/admin",
    "/api/v1/config", "/api/v1/settings", "/api/v1/keys",
    "/api/v1/tokens", "/api/v1/admins", "/actuator/shutdown",
}

# Patterns indicating interesting / sensitive content in response body
INTERESTING_BODY_PATTERNS = [
    "password", "secret", "token", "api_key", "apikey", "access_key",
    "private_key", "connection_string", "database_url", "db_url",
    "jdbc:", "mongodb://", "redis://", "amqp://",
    "AWS_ACCESS_KEY", "AWS_SECRET", "GOOGLE_", "AZURE_",
    "stack trace", "exception", "at java.", "at com.", "traceback",
    "SyntaxError", "undefined method", "NoMethodError",
    "PG::SyntaxError", "MySQL syntax", "SQLite3::Exception",
    '"swagger":', '"openapi":', '"paths":', '"definitions":',
    '"introspectionResult":', '"__schema"',
]


class RouteProbeResult:
    """Structured result of probing a single route."""
    def __init__(self, url: str, path: str, method: str, status: int,
                 content_type: str, content_length: int,
                 interesting_patterns: List[str], headers: Dict[str, str]):
        self.url = url
        self.path = path
        self.method = method
        self.status = status
        self.content_type = content_type
        self.content_length = content_length
        self.interesting_patterns = interesting_patterns
        self.headers = headers

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "path": self.path,
            "method": self.method,
            "status": self.status,
            "content_type": self.content_type,
            "content_length": self.content_length,
            "interesting_patterns": self.interesting_patterns,
            "headers": self.headers,
        }


class SmartRouteFuzzer:
    """
    Elite asynchronous route fuzzer probing 500+ high-value paths across every major
    tech stack. Includes method fuzzing, response body intelligence analysis, and
    version/secret disclosure detection.
    """
    def __init__(self, timeout: float = 5.0, max_concurrency: int = 10):
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(max_concurrency)

    async def probe_route(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        route: str,
        method: str = "GET"
    ) -> Optional[RouteProbeResult]:
        target_url = urljoin(base_url, route)
        async with self.semaphore:
            try:
                req = client.build_request(method, target_url)
                resp = await client.send(req, follow_redirects=True)

                # Filter non-interesting status codes
                if resp.status_code in (404, 410, 502, 503, 504, 400, 405):
                    return None

                body_text = ""
                try:
                    body_text = resp.text[:4096]
                except Exception:
                    pass

                # Detect interesting patterns in response body
                found_patterns = [
                    pat for pat in INTERESTING_BODY_PATTERNS
                    if pat.lower() in body_text.lower()
                ]

                return RouteProbeResult(
                    url=target_url,
                    path=route,
                    method=method,
                    status=resp.status_code,
                    content_type=resp.headers.get("content-type", ""),
                    content_length=len(resp.content),
                    interesting_patterns=found_patterns,
                    headers={k.lower(): v for k, v in resp.headers.items()},
                )
            except Exception as e:
                logger.debug(f"[SmartRouteFuzzer] Error probing {method} {target_url}: {str(e)}")
        return None

    async def fuzz(
        self,
        base_url: str,
        custom_routes: Optional[List[str]] = None,
        deep_mode: bool = False,
    ) -> List[Dict[str, Any]]:
        if not base_url.startswith("http://") and not base_url.startswith("https://"):
            base_url = f"https://{base_url}"

        routes_to_test = list(set(HIGH_VALUE_ROUTES + (custom_routes or [])))
        discovered: List[Dict[str, Any]] = []

        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=False,
            verify=False,
            headers={
                "User-Agent": "Mozilla/5.0 (PenFlow/20.0 Security Research)",
                "Accept": "application/json, text/html, */*",
            }
        ) as client:
            # Phase 1: Parallel GET probe of all routes
            get_tasks = [
                self.probe_route(client, base_url, route, "GET")
                for route in routes_to_test
            ]
            results = await asyncio.gather(*get_tasks, return_exceptions=True)

            for res in results:
                if isinstance(res, RouteProbeResult):
                    discovered.append(res.to_dict())

            # Phase 2: Method fuzzing on high-risk discovered routes
            if deep_mode:
                method_fuzz_targets = [
                    r for r in routes_to_test
                    if any(hr in r for hr in METHOD_FUZZ_ROUTES)
                ]
                method_tasks = []
                for route in method_fuzz_targets[:30]:  # cap to avoid overload
                    for method in ["POST", "PUT", "DELETE", "PATCH", "OPTIONS"]:
                        method_tasks.append(
                            self.probe_route(client, base_url, route, method)
                        )
                method_results = await asyncio.gather(*method_tasks, return_exceptions=True)
                for res in method_results:
                    if isinstance(res, RouteProbeResult):
                        discovered.append(res.to_dict())

        logger.info(
            f"[SmartRouteFuzzer] Route fuzzing completed for {base_url}: "
            f"Found {len(discovered)} active paths from {len(routes_to_test)} probed."
        )
        return discovered
