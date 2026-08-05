# Research Paper 22: Nested Object Mass Assignment in Complex DTO Structs

## Summary
When updating nested user profile preferences, supplying deeply nested properties like `{"user": {"organization": {"owner": true}}}` updates elevated entity structures.

## Tactical Patterns
- Target Technology: ASP.NET Core, Entity Framework
- Endpoint Pattern: `/api/v1/settings/profile`
- Endpoint Pattern: `/api/v1/organization/member`
- Endpoint Pattern: `/api/v1/preferences/update`
- Category: Mass Assignment, Privilege Escalation
