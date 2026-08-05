# Bug Bounty Research Report #043: Broken Function Level Authorization (BFLA) on Express

## Executive Summary
During an offensive security assessment targeting `Express` infrastructure, a high-severity **Broken Function Level Authorization (BFLA)** vulnerability was identified.

## Target Details & Vulnerability Surface
- **Vulnerability Category**: `bfla`
- **Target Technology**: `Express`
- **Affected Path / Endpoint**: `/api/v2/management/system/restart`
- **Scenario Description**: System management endpoint access control flaw

## Attack Vector & Technical Analysis
The target application deployed on `Express` exposed `/api/v2/management/system/restart`.
An attacker sends a crafted request exploiting `bfla` mechanisms.
The backend processing engine fails to enforce authorization boundaries, resulting in security exposure.

## Key Indicators & Extracted Patterns
- **Endpoint Pattern**: `/api/v2/management/system/restart`
- **Vulnerability Types**: `bfla`
- **Target Tech Stack**: `express`
