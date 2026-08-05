# Bug Bounty Research Report #238: Server-Side Template Injection (SSTI) on Spring Boot

## Executive Summary
During an offensive security assessment targeting `Spring Boot` infrastructure, a high-severity **Server-Side Template Injection (SSTI)** vulnerability was identified.

## Target Details & Vulnerability Surface
- **Vulnerability Category**: `ssti`
- **Target Technology**: `Spring Boot`
- **Affected Path / Endpoint**: `/api/v2/email/preview?content=`
- **Scenario Description**: Spring Expression Language (SpEL) ${7*7} evaluation

## Attack Vector & Technical Analysis
The target application deployed on `Spring Boot` exposed `/api/v2/email/preview?content=`.
An attacker sends a crafted request exploiting `ssti` mechanisms.
The backend processing engine fails to enforce authorization boundaries, resulting in security exposure.

## Key Indicators & Extracted Patterns
- **Endpoint Pattern**: `/api/v2/email/preview?content=`
- **Vulnerability Types**: `ssti`
- **Target Tech Stack**: `spring boot`
