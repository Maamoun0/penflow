# Bug Bounty Research Report #062: Broken Function Level Authorization (BFLA) on Spring Boot

## Executive Summary
During an offensive security assessment targeting `Spring Boot` infrastructure, a high-severity **Broken Function Level Authorization (BFLA)** vulnerability was identified.

## Target Details & Vulnerability Surface
- **Vulnerability Category**: `bfla`
- **Target Technology**: `Spring Boot`
- **Affected Path / Endpoint**: `/api/v2/super-admin/tenants/delete`
- **Scenario Description**: Super-admin tenant deletion method tampering

## Attack Vector & Technical Analysis
The target application deployed on `Spring Boot` exposed `/api/v2/super-admin/tenants/delete`.
An attacker sends a crafted request exploiting `bfla` mechanisms.
The backend processing engine fails to enforce authorization boundaries, resulting in security exposure.

## Key Indicators & Extracted Patterns
- **Endpoint Pattern**: `/api/v2/super-admin/tenants/delete`
- **Vulnerability Types**: `bfla`
- **Target Tech Stack**: `spring boot`
