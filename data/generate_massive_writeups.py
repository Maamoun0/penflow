import os

writeup_templates = [
    # 13
    ("writeup_13_grpc_web_auth_bypass.md", """# Research Paper 13: gRPC-Web Authentication Traversal & Protobuf Deserialization

## Summary
In modern microservice architectures utilizing gRPC-Web over HTTP/2, reverse proxies decode gRPC frames into standard REST calls. Improper authentication checks on internal Protobuf message fields allow unauthenticated callers to invoke internal management RPCs.

## Tactical Patterns
- Target Technology: gRPC-Web, Protocol Buffers, Go, Envoy Proxy
- Endpoint Pattern: `/grpc.v1.UserManagementService/GetUser`
- Endpoint Pattern: `/grpc.v1.AdminService/PurgeAuditLogs`
- Endpoint Pattern: `/grpc.v1.BillingService/UpdateSubscription`
- Category: BFLA, Authorization Bypass
"""),
    # 14
    ("writeup_14_saml_xml_signature_wrapping.md", """# Research Paper 14: SAML 2.0 XML Signature Wrapping (XSW) & SSO Assertion Takeover

## Summary
Enterprise Identity Providers (IdP) rely on SAML 2.0 assertions. XML Signature Wrapping (XSW) manipulates the XML document structure so that the signature validator checks a legitimate XML element while the application logic evaluates a cloned untrusted element.

## Tactical Patterns
- Target Technology: SAML 2.0, Okta, Shibboleth, Java Enterprise
- Endpoint Pattern: `/api/v1/auth/saml/sso`
- Endpoint Pattern: `/saml/acs/consume`
- Endpoint Pattern: `/api/v1/sso/callback`
- Category: Authentication Bypass, OAuth/JWT
"""),
    # 15
    ("writeup_15_graphql_depth_dos.md", """# Research Paper 15: GraphQL Recursive Nested Depth Resource Exhaustion

## Summary
GraphQL queries support circular relationships (e.g., User -> Posts -> Author -> Posts). Unrestricted query depth allows attackers to submit deeply nested queries that exhaust server CPU and memory allocations.

## Tactical Patterns
- Target Technology: GraphQL, Apollo Server, Hasura
- Endpoint Pattern: `/api/v2/graphql`
- Endpoint Pattern: `/graphql/v1`
- Endpoint Pattern: `/query/graphql`
- Category: GraphQL, Denial of Service
"""),
    # 16
    ("writeup_16_rate_limit_header_bypass.md", """# Research Paper 16: API Rate Limit Bypass via IP Header Rotation

## Summary
Web application firewalls (WAF) enforce rate limits based on client IP addresses derived from HTTP request headers. Rotating client headers on each request circumvents rate limiting mechanisms.

## Tactical Patterns
- Target Technology: Nginx, Cloudflare, Express.js
- Endpoint Pattern: `/api/v1/auth/forgot-password`
- Endpoint Pattern: `/api/v1/otp/send`
- Endpoint Pattern: `/api/v1/sms/verify`
- Category: Security Misconfiguration, BFLA
"""),
    # 17
    ("writeup_17_ssrf_dns_rebinding.md", """# Research Paper 17: SSRF Blacklist Bypass via Time-of-Check DNS Rebinding

## Summary
SSRF filters often perform a DNS lookup at validation time to check if an IP is private (127.0.0.1 or 169.254.169.254). DNS Rebinding exploits short TTLs to return a public IP during validation and a private IP during fetch.

## Tactical Patterns
- Target Technology: Python Requests, Node-Fetch, Cloud Services
- Endpoint Pattern: `/api/v1/url/preview`
- Endpoint Pattern: `/api/v1/webhooks/test`
- Endpoint Pattern: `/api/v1/export/pdf`
- Category: SSRF, Cloud Metadata
"""),
    # 18
    ("writeup_18_bola_batch_ids.md", """# Research Paper 18: BOLA Array Injection in Mass Retrieval APIs

## Summary
API endpoints accepting arrays of IDs (e.g. `{"ids": [101, 102]}`) validate authorization only for the first ID in the array while returning objects for all requested IDs in the response array.

## Tactical Patterns
- Target Technology: Ruby on Rails, Django REST Framework
- Endpoint Pattern: `/api/v1/orders/batch`
- Endpoint Pattern: `/api/v1/messages/bulk`
- Endpoint Pattern: `/api/v1/analytics/export`
- Category: IDOR, BOLA
"""),
    # 19
    ("writeup_19_jwt_jwks_spoofing.md", """# Research Paper 19: JWT Authorization Takeover via Custom 'jku' Header Spoofing

## Summary
The JWT specification allows the `jku` (JWK Set URL) header to point to a public key file. Insecure JWT verifiers accept arbitrary `jku` domain URLs, permitting attackers to host a rogue JWKS and sign forged administrative tokens.

## Tactical Patterns
- Target Technology: Node.js, Spring Boot, Auth0
- Endpoint Pattern: `/api/v1/auth/jwks`
- Endpoint Pattern: `/api/v1/users/admin`
- Endpoint Pattern: `/api/v1/token/validate`
- Category: OAuth/JWT, Authentication Bypass
"""),
    # 20
    ("writeup_20_cors_null_origin.md", """# Research Paper 20: CORS Exploitation via Null Origin Reflection in Sandboxed Iframes

## Summary
Servers configured to accept `Origin: null` for sandboxed iframes or local HTML files allow attackers to trigger cross-origin data extraction using `<iframe sandbox="allow-scripts">`.

## Tactical Patterns
- Target Technology: Modern Web Apps, CORS Headers
- Endpoint Pattern: `/api/v1/user/private-keys`
- Endpoint Pattern: `/api/v1/account/tokens`
- Endpoint Pattern: `/api/v1/profile/data`
- Category: CORS, Information Disclosure
"""),
    # 21
    ("writeup_21_race_condition_giftcard.md", """# Research Paper 21: Financial Race Condition in Multi-Threaded Gift Card Redemptions

## Summary
Simultaneous redemption of single-use promo codes across concurrent worker threads bypasses balance updates due to improper row locking in relational databases.

## Tactical Patterns
- Target Technology: E-Commerce APIs, PostgreSQL, MySQL
- Endpoint Pattern: `/api/v1/giftcards/apply`
- Endpoint Pattern: `/api/v1/promo/redeem`
- Endpoint Pattern: `/api/v1/checkout/discount`
- Category: Race Condition, TOCTOU
"""),
    # 22
    ("writeup_22_mass_assignment_nested.md", """# Research Paper 22: Nested Object Mass Assignment in Complex DTO Structs

## Summary
When updating nested user profile preferences, supplying deeply nested properties like `{"user": {"organization": {"owner": true}}}` updates elevated entity structures.

## Tactical Patterns
- Target Technology: ASP.NET Core, Entity Framework
- Endpoint Pattern: `/api/v1/settings/profile`
- Endpoint Pattern: `/api/v1/organization/member`
- Endpoint Pattern: `/api/v1/preferences/update`
- Category: Mass Assignment, Privilege Escalation
"""),
    # 23
    ("writeup_23_bfla_http_verb_tampering.md", """# Research Paper 23: BFLA Bypass via HTTP Verb Tampering (HEAD / OPTIONS / PUT)

## Summary
WAFs and security interceptors restricting POST requests to `/admin` routes fail to inspect HEAD, PUT, or PATCH requests, enabling unprivileged privilege escalation.

## Tactical Patterns
- Target Technology: REST APIs, Java Servlet Filters
- Endpoint Pattern: `/api/v1/admin/users`
- Endpoint Pattern: `/api/v1/roles/assign`
- Endpoint Pattern: `/api/v1/permissions/grant`
- Category: BFLA, Method Tampering
"""),
    # 24
    ("writeup_24_graphql_alias_overloading.md", """# Research Paper 24: GraphQL Alias Overloading for Authentication Brute-Force

## Summary
GraphQL aliases allow multiple queries in a single HTTP request (e.g. `a: login(...), b: login(...)`). This bypasses single-request rate limits and security logging.

## Tactical Patterns
- Target Technology: GraphQL, Node.js, Python FastAPI
- Endpoint Pattern: `/graphql`
- Endpoint Pattern: `/api/graphql/v1`
- Endpoint Pattern: `/v1/query`
- Category: GraphQL, Authentication Bypass
"""),
    # 25
    ("writeup_25_ssrf_gopher_redis.md", """# Research Paper 25: SSRF to Internal Redis Remote Code Execution via Gopher Protocol

## Summary
SSRF vulnerabilities supporting arbitrary URL schemas (such as `gopher://`) allow sending raw TCP payloads to internal Redis servers (`127.0.0.1:6379`).

## Tactical Patterns
- Target Technology: cURL, PHP, Python
- Endpoint Pattern: `/api/v1/fetch/avatar`
- Endpoint Pattern: `/api/v1/import/url`
- Endpoint Pattern: `/api/v1/proxy/request`
- Category: SSRF, Cloud Metadata
"""),
    # 26
    ("writeup_26_oauth_redirect_uri_bypass.md", """# Research Paper 26: OAuth 2.0 Account Takeover via Wildcard Redirect URI Validation

## Summary
Flaws in OAuth 2.0 `redirect_uri` validation (e.g., accepting `https://victim.com.attacker.com` or path traversal `https://victim.com/oauth/../callback`) result in authorization code leakage.

## Tactical Patterns
- Target Technology: OAuth 2.0, OpenID Connect
- Endpoint Pattern: `/oauth/v2/authorize`
- Endpoint Pattern: `/connect/authorize`
- Endpoint Pattern: `/sso/oauth/authorize`
- Category: OAuth/JWT, Authentication Bypass
"""),
    # 27
    ("writeup_27_idor_tenant_switching.md", """# Research Paper 27: Multi-Tenant Tenant-ID Header Injection IDOR

## Summary
Enterprise SaaS applications rely on custom HTTP headers (like `X-Tenant-ID` or `X-Organization-ID`) for multi-tenant data routing. Overriding this header leaks victim workspace data.

## Tactical Patterns
- Target Technology: SaaS Multi-Tenant Architectures
- Endpoint Pattern: `/api/v1/workspace/data`
- Endpoint Pattern: `/api/v1/projects/list`
- Endpoint Pattern: `/api/v1/reports/summary`
- Category: IDOR, BOLA
"""),
    # 28
    ("writeup_28_nosql_json_type_confusion.md", """# Research Paper 28: NoSQL Type Confusion in JSON Parameter Parsers

## Summary
Submitting JSON arrays or boolean flags instead of string scalar types (`{"password": true}`) causes NoSQL database drivers to return valid user documents without password matches.

## Tactical Patterns
- Target Technology: Node.js, Express, Mongoose, MongoDB
- Endpoint Pattern: `/api/v1/auth/login`
- Endpoint Pattern: `/api/v1/verify/token`
- Endpoint Pattern: `/api/v1/user/reset`
- Category: NoSQL Injection, Security Misconfiguration
"""),
    # 29
    ("writeup_29_websocket_unauthenticated_broadcast.md", """# Research Paper 29: Unauthenticated Ingestion in Real-Time Order Stream WebSockets

## Summary
WebSocket endpoints initializing connections without enforcing token validation expose confidential trading or order streams to unauthenticated listeners.

## Tactical Patterns
- Target Technology: WebSockets, Socket.io, Go Gorilla
- Endpoint Pattern: `/ws/v1/orders`
- Endpoint Pattern: `/stream/v1/trades`
- Endpoint Pattern: `/ws/v1/admin/logs`
- Category: WebSocket, Information Disclosure
"""),
    # 30
    ("writeup_30_jwt_blank_signature.md", """# Research Paper 30: Signature Omission Flaw in Dual-Algorithm JWT Parsers

## Summary
Certain JWT verification implementations split the token by dot (`.`) and ignore the signature segment entirely if the algorithm header is modified.

## Tactical Patterns
- Target Technology: Python PyJWT, Java JJWT
- Endpoint Pattern: `/api/v1/auth/verify`
- Endpoint Pattern: `/api/v1/user/settings`
- Endpoint Pattern: `/api/v1/session/refresh`
- Category: OAuth/JWT, Authentication Bypass
""")
]

target_dir = r"c:\Users\Maamoun\Downloads\antygravity\bug bounty\data\writeups"
os.makedirs(target_dir, exist_ok=True)

for fname, content in writeup_templates:
    path = os.path.join(target_dir, fname)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content.strip() + "\n")

print(f"Successfully generated {len(writeup_templates)} new detailed research writeups!")
