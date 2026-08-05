# Research Paper 25: SSRF to Internal Redis Remote Code Execution via Gopher Protocol

## Summary
SSRF vulnerabilities supporting arbitrary URL schemas (such as `gopher://`) allow sending raw TCP payloads to internal Redis servers (`127.0.0.1:6379`).

## Tactical Patterns
- Target Technology: cURL, PHP, Python
- Endpoint Pattern: `/api/v1/fetch/avatar`
- Endpoint Pattern: `/api/v1/import/url`
- Endpoint Pattern: `/api/v1/proxy/request`
- Category: SSRF, Cloud Metadata
