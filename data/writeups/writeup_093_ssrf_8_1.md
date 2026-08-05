# Bug Bounty Research Report #093: Server-Side Request Forgery (SSRF) on Node.js

## Executive Summary
During an offensive security assessment targeting `Node.js` infrastructure, a high-severity **Server-Side Request Forgery (SSRF)** vulnerability was identified.

## Target Details & Vulnerability Surface
- **Vulnerability Category**: `ssrf`
- **Target Technology**: `Node.js`
- **Affected Path / Endpoint**: `/api/v2/preview/site?domain=`
- **Scenario Description**: Site preview generator internal Redis 6379 port scanning

## Attack Vector & Technical Analysis
The target application deployed on `Node.js` exposed `/api/v2/preview/site?domain=`.
An attacker sends a crafted request exploiting `ssrf` mechanisms.
The backend processing engine fails to enforce authorization boundaries, resulting in security exposure.

## Key Indicators & Extracted Patterns
- **Endpoint Pattern**: `/api/v2/preview/site?domain=`
- **Vulnerability Types**: `ssrf`
- **Target Tech Stack**: `node.js`
