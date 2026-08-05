# Research Paper 28: NoSQL Type Confusion in JSON Parameter Parsers

## Summary
Submitting JSON arrays or boolean flags instead of string scalar types (`{"password": true}`) causes NoSQL database drivers to return valid user documents without password matches.

## Tactical Patterns
- Target Technology: Node.js, Express, Mongoose, MongoDB
- Endpoint Pattern: `/api/v1/auth/login`
- Endpoint Pattern: `/api/v1/verify/token`
- Endpoint Pattern: `/api/v1/user/reset`
- Category: NoSQL Injection, Security Misconfiguration
