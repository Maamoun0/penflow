# Research Paper 43: BFLA via API Version Downgrading (v2 to v1 Unprotected Endpoints)

## Summary
When organizations upgrade their API security policies on `/api/v2/` routes, older `/api/v1/` endpoints frequently remain active on the backend without strict role-based access control (RBAC). An unprivileged user can modify `/api/v2/admin/users` to `/api/v1/admin/users` to execute administrative actions.

## Tactical Patterns
- Target Technology: REST APIs, Express, Rails, FastAPI
- Endpoint Pattern: `/api/v1/admin/users`
- Endpoint Pattern: `/api/v1/billing/subscriptions`
- Endpoint Pattern: `/api/v1/organization/settings`
- Category: BFLA, Privilege Escalation
