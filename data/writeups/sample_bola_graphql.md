# Real-world Bug Bounty Writeup: Critical BOLA in Node.js GraphQL API

## Summary
In this security research writeup, I discovered a high-severity Broken Object Level Authorization (BOLA / IDOR) vulnerability in a Node.js GraphQL web application.

## Vulnerability Analysis
The target application exposed a GraphQL endpoint at `/graphql` and REST API routes under `/api/v1/users/profile?id=100`.
By sending requests as standard User B with the authorization token of User B, but targeting the profile ID of User A (`/api/v1/invoices/100`), the application returned confidential victim SSNs and invoice receipts.

## Key Takeaways & Tactical Patterns
- Target Technology: Node.js, Express, GraphQL
- Endpoint Patterns: `/api/v1/users/profile`, `/api/v1/invoices/100`, `/graphql`
- Vulnerability Category: BOLA / IDOR, GraphQL Schema Introspection
