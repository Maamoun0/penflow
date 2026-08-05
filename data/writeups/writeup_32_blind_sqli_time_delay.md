# Research Paper 32: Blind Time-Delay SQL Injection in Microservice Query Filter

## Summary
Microservices that construct dynamic SQL filters without prepared statements are susceptible to blind time-delay SQL injection. By injecting database sleep directives (`pg_sleep(5)`, `WAITFOR DELAY`), an attacker can infer sensitive records bit-by-bit.

## Tactical Patterns
- Target Technology: PostgreSQL, MySQL, Django, Spring
- Endpoint Pattern: `/api/v1/products/search?filter=active`
- Endpoint Pattern: `/api/v1/analytics/query?sort=date`
- Endpoint Pattern: `/api/v1/reports/export?range=all`
- Category: SQL Injection, Parameter Tampering
