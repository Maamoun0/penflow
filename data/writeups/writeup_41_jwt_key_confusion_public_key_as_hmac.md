# Research Paper 41: JWT Key Confusion Vulnerability (Asymmetric RSA Public Key as HMAC Secret)

## Summary
When a backend server accepts both RS256 and HS256 tokens, an attacker can modify the token header algorithm to HS256 and sign the token using the server's public RSA key (which is freely available via JWKS). The vulnerable verification library interprets the public key string as the HMAC secret key, validating the forged token.

## Tactical Patterns
- Target Technology: Node.js jsonwebtoken, Go jwt-go, Python PyJWT
- Endpoint Pattern: `/api/v1/auth/token`
- Endpoint Pattern: `/api/v1/user/profile`
- Endpoint Pattern: `/api/v1/admin/dashboard`
- Category: OAuth/JWT, Authentication Bypass
