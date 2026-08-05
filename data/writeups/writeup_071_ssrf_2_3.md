# Bug Bounty Research Report #071: Server-Side Request Forgery (SSRF) on Express

## Executive Summary
During an offensive security assessment targeting `Express` infrastructure, a high-severity **Server-Side Request Forgery (SSRF)** vulnerability was identified.

## Target Details & Vulnerability Surface
- **Vulnerability Category**: `ssrf`
- **Target Technology**: `Express`
- **Affected Path / Endpoint**: `/api/v2/webhook/test?target=`
- **Scenario Description**: Webhook tester internal network scanning

## Attack Vector & Technical Analysis
The target application deployed on `Express` exposed `/api/v2/webhook/test?target=`.
An attacker sends a crafted request exploiting `ssrf` mechanisms.
The backend processing engine fails to enforce authorization boundaries, resulting in security exposure.

## Key Indicators & Extracted Patterns
- **Endpoint Pattern**: `/api/v2/webhook/test?target=`
- **Vulnerability Types**: `ssrf`
- **Target Tech Stack**: `express`
