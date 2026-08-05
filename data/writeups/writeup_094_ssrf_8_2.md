# Bug Bounty Research Report #094: Server-Side Request Forgery (SSRF) on Spring Boot

## Executive Summary
During an offensive security assessment targeting `Spring Boot` infrastructure, a high-severity **Server-Side Request Forgery (SSRF)** vulnerability was identified.

## Target Details & Vulnerability Surface
- **Vulnerability Category**: `ssrf`
- **Target Technology**: `Spring Boot`
- **Affected Path / Endpoint**: `/api/v2/preview/site?domain=`
- **Scenario Description**: Site preview generator internal Redis 6379 port scanning

## Attack Vector & Technical Analysis
The target application deployed on `Spring Boot` exposed `/api/v2/preview/site?domain=`.
An attacker sends a crafted request exploiting `ssrf` mechanisms.
The backend processing engine fails to enforce authorization boundaries, resulting in security exposure.

## Key Indicators & Extracted Patterns
- **Endpoint Pattern**: `/api/v2/preview/site?domain=`
- **Vulnerability Types**: `ssrf`
- **Target Tech Stack**: `spring boot`
