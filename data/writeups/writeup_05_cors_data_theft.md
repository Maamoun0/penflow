# CORS Misconfiguration to Cross-Domain Authenticated Token Theft

## Executive Summary
A wild-card origin reflection misconfiguration with `Access-Control-Allow-Credentials: true` on `/api/v1/user/tokens`.

## Technical Deep Dive
Attacker hosted an exploit page fetching `https://target.com/api/v1/user/tokens`. Because the backend reflected `Origin: https://evil.com` alongside credentials allowance, the browser delivered the victim's Bearer token to evil.com.

## Key Indicators & Patterns
- Endpoint: `/api/v1/user/tokens`
- Vulnerability Type: `cors`, `info_disclosure`
- Target Tech: `express`, `node`
