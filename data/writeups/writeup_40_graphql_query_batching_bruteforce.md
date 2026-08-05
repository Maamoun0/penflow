# Research Paper 40: GraphQL Array Batching for OTP and Password Brute-Force

## Summary
GraphQL servers supporting JSON array batching execute multiple query operations within a single HTTP request. Because traditional WAF and IP rate limits count HTTP connections rather than internal query operations, an attacker can batch hundreds of login attempts in one request without triggering rate limits.

## Tactical Patterns
- Target Technology: GraphQL, Apollo Server, Express-GraphQL
- Endpoint Pattern: `/graphql`
- Endpoint Pattern: `/api/graphql`
- Endpoint Pattern: `/v1/query`
- Category: GraphQL, Rate Limit Bypass
