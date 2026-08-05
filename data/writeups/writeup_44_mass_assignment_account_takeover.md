# Research Paper 44: Mass Assignment Leading to Account Takeover via Email Verification Property

## Summary
In user profile update endpoints, ORM auto-binding blindly deserializes request JSON into the User entity. An attacker injecting `{"email_verified": true, "email": "victim@target.com"}` updates their account address to any target email without going through the confirmation link verification flow.

## Tactical Patterns
- Target Technology: Prisma, Hibernate, Ruby on Rails, Django
- Endpoint Pattern: `/api/v1/user/profile`
- Endpoint Pattern: `/api/v1/account/update`
- Endpoint Pattern: `/api/v1/users/me`
- Category: Mass Assignment, Account Takeover
