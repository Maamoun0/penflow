# Real-world Bug Bounty Writeup: Mass Assignment & BFLA Privilege Escalation

## Summary
During a security assessment on an enterprise web portal, I identified a Mass Assignment auto-binding vulnerability on `/api/v1/user/update`.

## Details
When updating standard user profile details, passing `"is_admin": true` or `"role": "admin"` in the JSON payload resulted in the server persisting the elevated administrative role. Furthermore, unprivileged users could trigger `/api/v1/admin/users/export` using POST method tampering.

## Tactical Patterns
- Target Technology: Spring Boot, REST API
- Endpoints: `/api/v1/user/update`, `/api/v1/admin/users/export`
- Category: Mass Assignment, BFLA
