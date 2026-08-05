# Bug Bounty Research Report #054: Broken Function Level Authorization (BFLA) on Spring Boot

## Executive Summary
During an offensive security assessment targeting `Spring Boot` infrastructure, a high-severity **Broken Function Level Authorization (BFLA)** vulnerability was identified.

## Target Details & Vulnerability Surface
- **Vulnerability Category**: `bfla`
- **Target Technology**: `Spring Boot`
- **Affected Path / Endpoint**: `/api/v1/users/{id}/promote-admin`
- **Scenario Description**: User privilege escalation endpoint tampering

## Attack Vector & Technical Analysis
The target application deployed on `Spring Boot` exposed `/api/v1/users/{id}/promote-admin`.
An attacker sends a crafted request exploiting `bfla` mechanisms.
The backend processing engine fails to enforce authorization boundaries, resulting in security exposure.

## Key Indicators & Extracted Patterns
- **Endpoint Pattern**: `/api/v1/users/{id}/promote-admin`
- **Vulnerability Types**: `bfla`
- **Target Tech Stack**: `spring boot`
