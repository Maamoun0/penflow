# Bug Bounty Research Report #017: Broken Object Level Authorization (BOLA / IDOR) on Node.js

## Executive Summary
During an offensive security assessment targeting `Node.js` infrastructure, a high-severity **Broken Object Level Authorization (BOLA / IDOR)** vulnerability was identified.

## Target Details & Vulnerability Surface
- **Vulnerability Category**: `idor`
- **Target Technology**: `Node.js`
- **Affected Path / Endpoint**: `/api/v1/billing/{account_id}/payment-methods`
- **Scenario Description**: Billing account identity swap

## Attack Vector & Technical Analysis
The target application deployed on `Node.js` exposed `/api/v1/billing/{account_id}/payment-methods`.
An attacker sends a crafted request exploiting `idor` mechanisms.
The backend processing engine fails to enforce authorization boundaries, resulting in security exposure.

## Key Indicators & Extracted Patterns
- **Endpoint Pattern**: `/api/v1/billing/{account_id}/payment-methods`
- **Vulnerability Types**: `idor`
- **Target Tech Stack**: `node.js`
