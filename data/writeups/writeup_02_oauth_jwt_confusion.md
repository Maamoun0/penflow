# Research Paper 02: OAuth 2.0 & JWT Signature Bypass via Algorithm Confusion

## Executive Summary
This paper documents real-world OAuth 2.0 and JWT authentication flaws. When microservices verify JSON Web Tokens using public key cryptography (RS256), improper library configuration allows attackers to switch the header algorithm (`alg: HS256` or `alg: none`) and sign the token using the server's public key as an HMAC secret.

## Tactical Vector Analysis
- Endpoint Pattern: `/oauth/v2/token`
- Endpoint Pattern: `/api/v1/auth/session`
- Endpoint Pattern: `/api/v1/user/me`

Omission of the `state` parameter during authorization code flow (`/oauth/authorize?response_type=code`) enables OAuth CSRF, allowing account takeover.

## Key Indicators
- Vulnerability Type: OAuth 2.0, JWT, Authentication Bypass
- Targeted Endpoints: `/oauth/v2/token`, `/api/v1/auth/session`, `/api/v1/user/me`
- Attack Technique: Header parameter forgery, None algorithm, State parameter omission
