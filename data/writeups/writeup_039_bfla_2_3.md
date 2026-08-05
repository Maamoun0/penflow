# Bug Bounty Research Report #039: Broken Function Level Authorization (BFLA) on Express

## Executive Summary
During an offensive security assessment targeting `Express` infrastructure, a high-severity **Broken Function Level Authorization (BFLA)** vulnerability was identified.

## Target Details & Vulnerability Surface
- **Vulnerability Category**: `bfla`
- **Target Technology**: `Express`
- **Affected Path / Endpoint**: `/api/v1/admin/roles/assign`
- **Scenario Description**: Role assignment API HTTP method override

## Attack Vector & Technical Analysis
The target application deployed on `Express` exposed `/api/v1/admin/roles/assign`.
An attacker sends a crafted request exploiting `bfla` mechanisms.
The backend processing engine fails to enforce authorization boundaries, resulting in security exposure.

## Key Indicators & Extracted Patterns
- **Endpoint Pattern**: `/api/v1/admin/roles/assign`
- **Vulnerability Types**: `bfla`
- **Target Tech Stack**: `express`
