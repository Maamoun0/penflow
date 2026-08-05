# Bug Bounty Research Report #034: Broken Function Level Authorization (BFLA) on Spring Boot

## Executive Summary
During an offensive security assessment targeting `Spring Boot` infrastructure, a high-severity **Broken Function Level Authorization (BFLA)** vulnerability was identified.

## Target Details & Vulnerability Surface
- **Vulnerability Category**: `bfla`
- **Target Technology**: `Spring Boot`
- **Affected Path / Endpoint**: `/admin/users/export`
- **Scenario Description**: Administrative CSV export endpoint verb tampering

## Attack Vector & Technical Analysis
The target application deployed on `Spring Boot` exposed `/admin/users/export`.
An attacker sends a crafted request exploiting `bfla` mechanisms.
The backend processing engine fails to enforce authorization boundaries, resulting in security exposure.

## Key Indicators & Extracted Patterns
- **Endpoint Pattern**: `/admin/users/export`
- **Vulnerability Types**: `bfla`
- **Target Tech Stack**: `spring boot`
