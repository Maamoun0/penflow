# Research Paper 30: Signature Omission Flaw in Dual-Algorithm JWT Parsers

## Summary
Certain JWT verification implementations split the token by dot (`.`) and ignore the signature segment entirely if the algorithm header is modified.

## Tactical Patterns
- Target Technology: Python PyJWT, Java JJWT
- Endpoint Pattern: `/api/v1/auth/verify`
- Endpoint Pattern: `/api/v1/user/settings`
- Endpoint Pattern: `/api/v1/session/refresh`
- Category: OAuth/JWT, Authentication Bypass
