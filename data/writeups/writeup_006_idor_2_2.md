# Bug Bounty Research Report #006: Broken Object Level Authorization (BOLA / IDOR) on Spring Boot

## Executive Summary
During an offensive security assessment targeting `Spring Boot` infrastructure, a high-severity **Broken Object Level Authorization (BOLA / IDOR)** vulnerability was identified.

## Target Details & Vulnerability Surface
- **Vulnerability Category**: `idor`
- **Target Technology**: `Spring Boot`
- **Affected Path / Endpoint**: `/api/v2/accounts/{uuid}/settings`
- **Scenario Description**: UUID object reference cross-tenant access

## Attack Vector & Technical Analysis
The target application deployed on `Spring Boot` exposed `/api/v2/accounts/{uuid}/settings`.
An attacker sends a crafted request exploiting `idor` mechanisms.
The backend processing engine fails to enforce authorization boundaries, resulting in security exposure.

## Key Indicators & Extracted Patterns
- **Endpoint Pattern**: `/api/v2/accounts/{uuid}/settings`
- **Vulnerability Types**: `idor`
- **Target Tech Stack**: `spring boot`
