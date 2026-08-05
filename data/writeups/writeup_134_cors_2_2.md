# Bug Bounty Research Report #134: CORS Misconfiguration on Spring Boot

## Executive Summary
During an offensive security assessment targeting `Spring Boot` infrastructure, a high-severity **CORS Misconfiguration** vulnerability was identified.

## Target Details & Vulnerability Surface
- **Vulnerability Category**: `cors`
- **Target Technology**: `Spring Boot`
- **Affected Path / Endpoint**: `/api/v2/auth/session`
- **Scenario Description**: Null origin CORS policy bypass

## Attack Vector & Technical Analysis
The target application deployed on `Spring Boot` exposed `/api/v2/auth/session`.
An attacker sends a crafted request exploiting `cors` mechanisms.
The backend processing engine fails to enforce authorization boundaries, resulting in security exposure.

## Key Indicators & Extracted Patterns
- **Endpoint Pattern**: `/api/v2/auth/session`
- **Vulnerability Types**: `cors`
- **Target Tech Stack**: `spring boot`
