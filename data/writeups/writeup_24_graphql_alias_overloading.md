# Research Paper 24: GraphQL Alias Overloading for Authentication Brute-Force

## Summary
GraphQL aliases allow multiple queries in a single HTTP request (e.g. `a: login(...), b: login(...)`). This bypasses single-request rate limits and security logging.

## Tactical Patterns
- Target Technology: GraphQL, Node.js, Python FastAPI
- Endpoint Pattern: `/graphql`
- Endpoint Pattern: `/api/graphql/v1`
- Endpoint Pattern: `/v1/query`
- Category: GraphQL, Authentication Bypass
