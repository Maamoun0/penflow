# Bug Bounty Research Report #049: Broken Function Level Authorization (BFLA) on Node.js

## Executive Summary
During an offensive security assessment targeting `Node.js` infrastructure, a high-severity **Broken Function Level Authorization (BFLA)** vulnerability was identified.

## Target Details & Vulnerability Surface
- **Vulnerability Category**: `bfla`
- **Target Technology**: `Node.js`
- **Affected Path / Endpoint**: `/api/v2/audit/logs/purge`
- **Scenario Description**: Audit log purge administrative endpoint exposure

## Attack Vector & Technical Analysis
The target application deployed on `Node.js` exposed `/api/v2/audit/logs/purge`.
An attacker sends a crafted request exploiting `bfla` mechanisms.
The backend processing engine fails to enforce authorization boundaries, resulting in security exposure.

## Key Indicators & Extracted Patterns
- **Endpoint Pattern**: `/api/v2/audit/logs/purge`
- **Vulnerability Types**: `bfla`
- **Target Tech Stack**: `node.js`
