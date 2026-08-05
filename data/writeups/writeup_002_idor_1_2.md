# Bug Bounty Research Report #002: Broken Object Level Authorization (BOLA / IDOR) on Spring Boot

## Executive Summary
During an offensive security assessment targeting `Spring Boot` infrastructure, a high-severity **Broken Object Level Authorization (BOLA / IDOR)** vulnerability was identified.

## Target Details & Vulnerability Surface
- **Vulnerability Category**: `idor`
- **Target Technology**: `Spring Boot`
- **Affected Path / Endpoint**: `/api/v1/users/{id}/profile`
- **Scenario Description**: Sequential integer ID parameter swap

## Attack Vector & Technical Analysis
The target application deployed on `Spring Boot` exposed `/api/v1/users/{id}/profile`.
An attacker sends a crafted request exploiting `idor` mechanisms.
The backend processing engine fails to enforce authorization boundaries, resulting in security exposure.

## Key Indicators & Extracted Patterns
- **Endpoint Pattern**: `/api/v1/users/{id}/profile`
- **Vulnerability Types**: `idor`
- **Target Tech Stack**: `spring boot`
