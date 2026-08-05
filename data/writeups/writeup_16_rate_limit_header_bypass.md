# Research Paper 16: API Rate Limit Bypass via IP Header Rotation

## Summary
Web application firewalls (WAF) enforce rate limits based on client IP addresses derived from HTTP request headers. Rotating client headers on each request circumvents rate limiting mechanisms.

## Tactical Patterns
- Target Technology: Nginx, Cloudflare, Express.js
- Endpoint Pattern: `/api/v1/auth/forgot-password`
- Endpoint Pattern: `/api/v1/otp/send`
- Endpoint Pattern: `/api/v1/sms/verify`
- Category: Security Misconfiguration, BFLA
