# Broken Function Level Authorization (BFLA) via Verb Tampering

## Executive Summary
An unprivileged standard user achieved administrative access by overriding the HTTP method on `/admin/users/export`.

## Technical Deep Dive
Direct GET requests returned HTTP 403 Forbidden. However, sending a POST request with header `X-HTTP-Method-Override: GET` or using `POST` method directly on `/admin/users/export` bypassed the RBAC filter.

## Key Indicators & Patterns
- Endpoint: `/admin/users/export`
- Vulnerability Type: `bfla`, `privilege_escalation`, `method_tampering`
- Target Tech: `django`, `python`
