# Bug Bounty Research Report #035: Broken Function Level Authorization (BFLA) on Express

## Executive Summary
During an offensive security assessment targeting `Express` infrastructure, a high-severity **Broken Function Level Authorization (BFLA)** vulnerability was identified.

## Target Details & Vulnerability Surface
- **Vulnerability Category**: `bfla`
- **Target Technology**: `Express`
- **Affected Path / Endpoint**: `/admin/users/export`
- **Scenario Description**: Administrative CSV export endpoint verb tampering

## Attack Vector & Technical Analysis
The target application deployed on `Express` exposed `/admin/users/export`.
An attacker sends a crafted request exploiting `bfla` mechanisms.
The backend processing engine fails to enforce authorization boundaries, resulting in security exposure.

## Key Indicators & Extracted Patterns
- **Endpoint Pattern**: `/admin/users/export`
- **Vulnerability Types**: `bfla`
- **Target Tech Stack**: `express`
