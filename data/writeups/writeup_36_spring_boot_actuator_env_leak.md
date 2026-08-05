# Research Paper 36: Spring Boot Actuator Environment Secret Disclosure

## Summary
Unprotected Spring Boot Actuator management endpoints (specifically `/actuator/env` and `/actuator/heapdump`) expose live server configuration, database credentials, AWS access keys, and internal service tokens to unauthorized public visitors.

## Tactical Patterns
- Target Technology: Java, Spring Boot, Spring Actuator
- Endpoint Pattern: `/actuator/env`
- Endpoint Pattern: `/actuator/health`
- Endpoint Pattern: `/actuator/httptrace`
- Category: Information Disclosure, Misconfiguration
