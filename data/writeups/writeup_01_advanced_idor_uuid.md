# Research Paper 01: Advanced BOLA / IDOR in UUID-Based Multi-Tenant Enterprise APIs

## Executive Summary
In UUID-based REST API architectures, developers often assume 128-bit random UUIDs provide authorization by obscurity. This research writeup demonstrates how cross-session token swapping and nested parameter introspection expose Broken Object Level Authorization (BOLA / IDOR).

## Tactical Vector Analysis
- Endpoint Pattern: `/api/v2/tenants/profile`
- Endpoint Pattern: `/api/v1/invoices/export`
- Endpoint Pattern: `/api/v1/users/documents`

By taking the JWT authorization token of Identity B and requesting Identity A's UUID parameter (`/api/v1/documents?id=usr_998877`), the server omitted user-ownership validation at the data access object (DAO) level.

## Key Indicators
- Vulnerability Type: IDOR, BOLA, Multi-Tenant Authorization
- Targeted Endpoints: `/api/v2/tenants/profile`, `/api/v1/invoices/export`, `/api/v1/users/documents`
- Primary Identifiers: `user_id`, `account_id`, `doc_id`, `tenant_id`
