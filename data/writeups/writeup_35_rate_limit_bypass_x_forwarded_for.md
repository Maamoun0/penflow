# Research Paper 35: Rate Limit Bypass via X-Forwarded-For IP Spoofing on OTP Verification

## Summary
When API gateways rely on untrusted client headers (such as `X-Forwarded-For` or `X-Real-IP`) to track client request counts, attackers can rotate arbitrary IP addresses on each attempt. This completely bypasses brute-force protections on SMS/email OTP verification endpoints.

## Tactical Patterns
- Target Technology: Express-rate-limit, NGINX rate-limit, Kong Gateway
- Endpoint Pattern: `/api/v1/auth/verify-otp`
- Endpoint Pattern: `/api/v1/password/reset`
- Endpoint Pattern: `/api/v1/auth/mfa/challenge`
- Category: Rate Limit, Anti-Automation Bypass
