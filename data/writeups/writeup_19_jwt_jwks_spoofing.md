# Research Paper 19: JWT Authorization Takeover via Custom 'jku' Header Spoofing

## Summary
The JWT specification allows the `jku` (JWK Set URL) header to point to a public key file. Insecure JWT verifiers accept arbitrary `jku` domain URLs, permitting attackers to host a rogue JWKS and sign forged administrative tokens.

## Tactical Patterns
- Target Technology: Node.js, Spring Boot, Auth0
- Endpoint Pattern: `/api/v1/auth/jwks`
- Endpoint Pattern: `/api/v1/users/admin`
- Endpoint Pattern: `/api/v1/token/validate`
- Category: OAuth/JWT, Authentication Bypass
