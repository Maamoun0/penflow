# Bug Bounty Research Report #024: Broken Object Level Authorization (BOLA / IDOR) on Django

## Executive Summary
During an offensive security assessment targeting `Django` infrastructure, a high-severity **Broken Object Level Authorization (BOLA / IDOR)** vulnerability was identified.

## Target Details & Vulnerability Surface
- **Vulnerability Category**: `idor`
- **Target Technology**: `Django`
- **Affected Path / Endpoint**: `/api/v2/messages/{msg_id}`
- **Scenario Description**: Private message inbox enumeration

## Attack Vector & Technical Analysis
The target application deployed on `Django` exposed `/api/v2/messages/{msg_id}`.
An attacker sends a crafted request exploiting `idor` mechanisms.
The backend processing engine fails to enforce authorization boundaries, resulting in security exposure.

## Key Indicators & Extracted Patterns
- **Endpoint Pattern**: `/api/v2/messages/{msg_id}`
- **Vulnerability Types**: `idor`
- **Target Tech Stack**: `django`
