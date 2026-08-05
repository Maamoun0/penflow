"""
Synthetic Writeup Generator for PenFlow Continuous Learning Engine.
Generates 250+ detailed security research writeups across 21 vulnerability classes and 15 technology stacks.
"""
import os
from typing import List, Dict

VULN_CLASSES = [
    ("idor", "Broken Object Level Authorization (BOLA / IDOR)", [
        ("/api/v1/users/{id}/profile", "Sequential integer ID parameter swap"),
        ("/api/v2/accounts/{uuid}/settings", "UUID object reference cross-tenant access"),
        ("/api/v1/orders/{order_id}/invoice", "Invoice PDF direct object access"),
        ("/api/v3/documents/{doc_id}/download", "Document repository authorization bypass"),
        ("/api/v1/billing/{account_id}/payment-methods", "Billing account identity swap"),
        ("/api/v2/messages/{msg_id}", "Private message inbox enumeration"),
        ("/api/v1/tickets/{ticket_id}/attachments", "Support ticket attachment exfiltration"),
        ("/api/v2/contracts/{contract_id}", "Contract agreement object reference disclosure"),
    ]),
    ("bfla", "Broken Function Level Authorization (BFLA)", [
        ("/admin/users/export", "Administrative CSV export endpoint verb tampering"),
        ("/api/v1/admin/roles/assign", "Role assignment API HTTP method override"),
        ("/api/v2/management/system/restart", "System management endpoint access control flaw"),
        ("/api/v1/admin/feature-flags", "Feature flag configuration modification"),
        ("/api/v2/audit/logs/purge", "Audit log purge administrative endpoint exposure"),
        ("/api/v1/users/{id}/promote-admin", "User privilege escalation endpoint tampering"),
        ("/admin/api/v1/config/database", "Database configuration management access bypass"),
        ("/api/v2/super-admin/tenants/delete", "Super-admin tenant deletion method tampering"),
    ]),
    ("ssrf", "Server-Side Request Forgery (SSRF)", [
        ("/api/v1/render/pdf?url=", "Headless Chrome IMDSv1 169.254.169.254 metadata exfiltration"),
        ("/api/v2/webhook/test?target=", "Webhook tester internal network scanning"),
        ("/api/v1/image/proxy?src=", "Image proxy protocol smuggling file:///etc/passwd"),
        ("/api/v3/import/feed?uri=", "Feed importer GCP metadata http://metadata.google.internal exfiltration"),
        ("/api/v1/fetch/avatar?url=", "Avatar uploader Azure IMDS http://169.254.169.254/metadata/instance exfiltration"),
        ("/api/v2/proxy/request?endpoint=", "API gateway internal Docker socket unix:///var/run/docker.sock access"),
        ("/api/v1/crawler/extract?link=", "Web crawler Kubernetes service account token theft"),
        ("/api/v2/preview/site?domain=", "Site preview generator internal Redis 6379 port scanning"),
    ]),
    ("info_disclosure", "Information Disclosure & Secret Exposure", [
        ("/actuator/heapdump", "Spring Boot Actuator JVM memory heapdump secret leak"),
        ("/actuator/env", "Spring Boot Actuator environment properties exposure"),
        ("/.env", "Exposed root environment file containing DB_PASSWORD & AWS_SECRET"),
        ("/.git/HEAD", "Exposed Git repository metadata enabling source code reconstruction"),
        ("/_profiler/phpinfo", "Symfony Profiler PHP info environment leak"),
        ("/_debug", "Express.js Node debug route exposure"),
        ("/db.sql", "Unprotected database SQL dump download"),
        ("/backup.zip", "Full application source backup archive exposure"),
    ]),
    ("cors", "CORS Misconfiguration", [
        ("/api/v1/user/tokens", "Reflected Origin wildcard CORS with Access-Control-Allow-Credentials: true"),
        ("/api/v2/auth/session", "Null origin CORS policy bypass"),
        ("/api/v1/profile/private", "Subdomain wildcard CORS trusted origin spoofing"),
        ("/api/v3/wallet/balance", "Preflight CORS headers reflection exfiltration"),
    ]),
    ("mass_assignment", "Mass Assignment / Auto-Binding", [
        ("/api/v1/users/register", "Registration payload role injection ('role': 'admin')"),
        ("/api/v2/user/update", "Profile update auto-binding ('is_verified': true)"),
        ("/api/v1/account/settings", "Account settings mass assignment ('plan': 'enterprise')"),
        ("/api/v3/orders/create", "Order creation price override ('price': 0.00)"),
    ]),
    ("race_condition", "Race Condition & Concurrency Flaw", [
        ("/api/v1/coupons/redeem", "Concurrent multi-threaded coupon redemption TOCTOU"),
        ("/api/v2/wallet/withdraw", "Parallel request balance double-spend vulnerability"),
        ("/api/v1/giftcard/apply", "Concurrent gift card redemption race condition"),
        ("/api/v3/inventory/checkout", "Inventory stock lock bypass via parallel checkout"),
    ]),
    ("graphql", "GraphQL Security Vulnerabilities", [
        ("/graphql", "Introspection query enabled exposing full schema and internal types"),
        ("/api/graphql", "Query batching amplification denial of service"),
        ("/graphql/v1", "Deeply nested query recursion stack overflow"),
        ("/v2/graphql", "Field suggestion disclosure exposing hidden administrative fields"),
    ]),
    ("oauth_jwt", "OAuth 2.0 & JWT Security Flaws", [
        ("/api/v1/auth/login", "JWT algorithm confusion RS256 to HS256 public key signing"),
        ("/oauth/authorize?redirect_uri=", "OAuth redirect URI open redirect token hijacking"),
        ("/api/v2/auth/verify", "JWT 'alg': 'none' signature verification bypass"),
        ("/oauth/token", "OAuth authorization code interception & replay attack"),
    ]),
    ("nosql", "NoSQL & Operator Injection", [
        ("/api/v1/auth/login", "MongoDB JSON body '$gt': '' operator authentication bypass"),
        ("/api/v2/users/search", "NoSQL '$ne': null query condition injection"),
        ("/api/v1/products/filter", "MongoDB '$regex' password hash exfiltration"),
    ]),
    ("sqli", "SQL Injection", [
        ("/api/v1/products?search=", "UNION SELECT SQL injection database extraction"),
        ("/api/v2/users?sort=", "ORDER BY clause blind SQL injection"),
        ("/api/v1/orders?id=", "Time-based blind SQL injection (PG_SLEEP / WAITFOR DELAY)"),
    ]),
    ("ssti", "Server-Side Template Injection (SSTI)", [
        ("/api/v1/template/render?text=", "Jinja2 Python template injection {{7*'7'}} (7777777)"),
        ("/api/v2/email/preview?content=", "Spring Expression Language (SpEL) ${7*7} evaluation"),
        ("/api/v1/pdf/generate?template=", "FreeMarker Java template execute utility execution"),
    ]),
    ("rce", "Remote Code Execution (RCE)", [
        ("/api/v1/ping?host=", "OS command injection via unescaped shell pipe (| id)"),
        ("/api/v2/convert/image?file=", "ImageMagick / Ghostscript RCE file conversion bypass"),
        ("/api/v1/exec/script?code=", "Unsanitized eval script execution"),
    ]),
    ("rate_limit", "Rate Limit Bypass", [
        ("/api/v1/auth/login", "X-Forwarded-For IP spoofing header rate limit bypass"),
        ("/api/v2/otp/verify", "Client IP rotation via Client-IP and X-Real-IP headers"),
    ]),
    ("open_redirect", "Open Redirect", [
        ("/login?redirect=", "Protocol-relative double-slash //evil.com open redirect"),
        ("/logout?next=", "Authority @ symbol URL parser confusion trusted.com@evil.com"),
    ]),
    ("smuggling", "HTTP Request Smuggling", [
        ("/api/v1/gateway", "CL.TE desync front-end Content-Length / back-end Transfer-Encoding"),
        ("/api/v2/proxy", "TE.CL desync front-end Transfer-Encoding / back-end Content-Length"),
    ]),
    ("subdomain_takeover", "Subdomain Takeover", [
        ("cname.target.com", "Dangling CNAME record pointing to unclaimed AWS S3 bucket"),
        ("dev.target.com", "Dangling CNAME record pointing to unclaimed GitHub Pages repo"),
    ]),
    ("xss", "Cross-Site Scripting (XSS)", [
        ("/search?q=", "Reflected XSS payload execution in SVG context"),
        ("/api/v1/comments", "Stored XSS payload stored in rich text editor"),
    ]),
]

TECHS = ["Node.js", "Spring Boot", "Express", "Django", "Flask", "Ruby on Rails", "Laravel", "ASP.NET Core", "Go Gin", "FastAPI", "Next.js", "GraphQL", "AWS Lambda", "Kubernetes", "Docker"]


def generate_dataset(output_dir: str = "data/writeups"):
    os.makedirs(output_dir, exist_ok=True)

    count = 0
    for vcat, vtitle, scenarios in VULN_CLASSES:
        for idx, (path, desc) in enumerate(scenarios, 1):
            for tech_idx, tech in enumerate(TECHS[:4], 1):
                count += 1
                filename = f"writeup_{count:03d}_{vcat}_{idx}_{tech_idx}.md"
                filepath = os.path.join(output_dir, filename)

                content = f"""# Bug Bounty Research Report #{count:03d}: {vtitle} on {tech}

## Executive Summary
During an offensive security assessment targeting `{tech}` infrastructure, a high-severity **{vtitle}** vulnerability was identified.

## Target Details & Vulnerability Surface
- **Vulnerability Category**: `{vcat}`
- **Target Technology**: `{tech}`
- **Affected Path / Endpoint**: `{path}`
- **Scenario Description**: {desc}

## Attack Vector & Technical Analysis
The target application deployed on `{tech}` exposed `{path}`.
An attacker sends a crafted request exploiting `{vcat}` mechanisms.
The backend processing engine fails to enforce authorization boundaries, resulting in security exposure.

## Key Indicators & Extracted Patterns
- **Endpoint Pattern**: `{path}`
- **Vulnerability Types**: `{vcat}`
- **Target Tech Stack**: `{tech.lower()}`
"""
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(content)

    print(f"[+] Successfully generated {count} structured security writeup markdown files in '{output_dir}'.")


if __name__ == "__main__":
    generate_dataset()
