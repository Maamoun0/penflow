# Research Paper 27: Multi-Tenant Tenant-ID Header Injection IDOR

## Summary
Enterprise SaaS applications rely on custom HTTP headers (like `X-Tenant-ID` or `X-Organization-ID`) for multi-tenant data routing. Overriding this header leaks victim workspace data.

## Tactical Patterns
- Target Technology: SaaS Multi-Tenant Architectures
- Endpoint Pattern: `/api/v1/workspace/data`
- Endpoint Pattern: `/api/v1/projects/list`
- Endpoint Pattern: `/api/v1/reports/summary`
- Category: IDOR, BOLA
