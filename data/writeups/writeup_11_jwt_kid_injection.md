# Research Paper 11: JWT Header 'kid' Parameter Path Traversal & SQL Injection

## Executive Summary
The JSON Web Token (JWT) specification permits an optional `kid` (Key ID) header parameter to instruct servers which public key or database secret to select for signature verification.

## Tactical Vector Analysis
- Endpoint Pattern: `/api/v1/auth/jwt/refresh`
- Endpoint Pattern: `/api/v1/user/dashboard`
- Endpoint Pattern: `/api/v1/tokens/verify`

When backend services use `kid` to construct filesystem paths (`/keys/` + header.kid) or execute SQL queries (`SELECT secret FROM keys WHERE id = '` + header.kid + `'`), injecting path traversal sequences (`"kid": "../../dev/null"`) forces signature verification against empty or known static secrets (`\n`), allowing signature forgery.

## Key Indicators
- Vulnerability Type: JWT, Key ID Injection, Path Traversal, SQL Injection
- Targeted Endpoints: `/api/v1/auth/jwt/refresh`, `/api/v1/user/dashboard`, `/api/v1/tokens/verify`
- Attack Technique: `kid` header parameter manipulation, static file mapping
