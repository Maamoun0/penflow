# Research Paper 09: NoSQL Operator Injection ($gt, $ne, $regex) Authentication Bypass

## Executive Summary
NoSQL databases like MongoDB do not use standard SQL syntax. However, when web applications pass unsanitized client JSON directly into database queries (`db.users.find(req.body)`), attackers can inject MongoDB query operators to bypass authentication.

## Tactical Vector Analysis
- Endpoint Pattern: `/api/v1/auth/login`
- Endpoint Pattern: `/api/v1/user/search`
- Endpoint Pattern: `/api/v1/reset-password/verify`

Injecting JSON query operators (`{"username": "admin", "password": {"$ne": ""}}` or `{"email": {"$regex": "^admin"}}`) causes the query evaluation to return true without knowledge of valid passwords or secret reset tokens.

## Key Indicators
- Vulnerability Type: NoSQL Injection, MongoDB Operator Injection, Authentication Bypass
- Targeted Endpoints: `/api/v1/auth/login`, `/api/v1/user/search`, `/api/v1/reset-password/verify`
- Operator Payload Vectors: `$ne`, `$gt`, `$regex`, `$where`, `$exists`
