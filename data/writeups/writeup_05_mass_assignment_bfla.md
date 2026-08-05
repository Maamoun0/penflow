# Research Paper 05: Mass Assignment & BFLA Method Tampering in Microservices

## Executive Summary
Modern MVC frameworks (Spring Boot, ASP.NET Core, Ruby on Rails) provide object auto-binding features that automatically bind JSON payloads to internal domain models.

## Tactical Vector Analysis
- Endpoint Pattern: `/api/v1/user/account`
- Endpoint Pattern: `/api/v1/admin/roles`
- Endpoint Pattern: `/api/v1/system/config`

By injecting privilege fields (`"role": "admin"`, `"is_admin": true`, `"balance": 999999`), attackers alter database state. Furthermore, switching HTTP methods from GET to POST/PUT bypasses Broken Function Level Authorization (BFLA) checks on management routes.

## Key Indicators
- Vulnerability Type: Mass Assignment, BFLA, Method Tampering
- Targeted Endpoints: `/api/v1/user/account`, `/api/v1/admin/roles`, `/api/v1/system/config`
- Parameter Injection: `role`, `is_admin`, `verified`, `balance`, `tier`
