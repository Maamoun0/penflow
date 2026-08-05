# Research Paper 37: Open Redirect in OAuth Callback Leading to Authorization Code Theft

## Summary
Improper URL validation in OAuth 2.0 authorization redirect handling (`redirect_uri` or `next` parameters) allows attackers to supply protocol-relative URLs (`//attacker.com`) or domain suffixes (`@attacker.com`). This redirects authenticating users to malicious domains and leaks temporary authorization codes via Referer headers or URL hash fragments.

## Tactical Patterns
- Target Technology: OAuth 2.0, OpenID Connect, Spring Security
- Endpoint Pattern: `/oauth/authorize`
- Endpoint Pattern: `/api/v1/auth/callback`
- Endpoint Pattern: `/api/v1/redirect`
- Category: Open Redirect, OAuth Misconfiguration
