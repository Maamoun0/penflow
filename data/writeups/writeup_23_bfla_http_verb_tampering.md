# Research Paper 23: BFLA Bypass via HTTP Verb Tampering (HEAD / OPTIONS / PUT)

## Summary
WAFs and security interceptors restricting POST requests to `/admin` routes fail to inspect HEAD, PUT, or PATCH requests, enabling unprivileged privilege escalation.

## Tactical Patterns
- Target Technology: REST APIs, Java Servlet Filters
- Endpoint Pattern: `/api/v1/admin/users`
- Endpoint Pattern: `/api/v1/roles/assign`
- Endpoint Pattern: `/api/v1/permissions/grant`
- Category: BFLA, Method Tampering
