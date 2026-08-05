# Research Paper 31: NoSQL Operator Injection in JSON Authentication Endpoint

## Summary
In modern Node.js and MongoDB applications, parsing unvalidated JSON request bodies allows attackers to submit query operators such as `{"$ne": null}` instead of string values. This satisfies the database query without knowledge of the valid password, resulting in complete authentication bypass.

## Tactical Patterns
- Target Technology: Node.js, Express, MongoDB, Mongoose
- Endpoint Pattern: `/api/v1/auth/login`
- Endpoint Pattern: `/api/v1/admin/authenticate`
- Endpoint Pattern: `/api/v1/session/create`
- Category: NoSQL Injection, Authentication Bypass
