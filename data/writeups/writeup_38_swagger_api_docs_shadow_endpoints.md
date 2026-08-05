# Research Paper 38: Shadow API Endpoint Enumeration via Exposed Swagger UI & OpenAPI Docs

## Summary
Developers frequently leave Swagger UI or OpenAPI documentation (`/v3/api-docs`, `/swagger-ui.html`, `/openapi.json`) exposed in production. These schema files document internal endpoints, administrative parameters, and deprecated API versions that lack authentication filters.

## Tactical Patterns
- Target Technology: Swagger, OpenAPI, FastAPI, SpringDoc
- Endpoint Pattern: `/v3/api-docs`
- Endpoint Pattern: `/swagger/v1/swagger.json`
- Endpoint Pattern: `/api-docs`
- Category: Information Disclosure, Reconnaissance
