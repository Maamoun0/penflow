# Research Paper 26: OAuth 2.0 Account Takeover via Wildcard Redirect URI Validation

## Summary
Flaws in OAuth 2.0 `redirect_uri` validation (e.g., accepting `https://victim.com.attacker.com` or path traversal `https://victim.com/oauth/../callback`) result in authorization code leakage.

## Tactical Patterns
- Target Technology: OAuth 2.0, OpenID Connect
- Endpoint Pattern: `/oauth/v2/authorize`
- Endpoint Pattern: `/connect/authorize`
- Endpoint Pattern: `/sso/oauth/authorize`
- Category: OAuth/JWT, Authentication Bypass
