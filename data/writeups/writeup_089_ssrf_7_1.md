# Bug Bounty Research Report #089: Server-Side Request Forgery (SSRF) on Node.js

## Executive Summary
During an offensive security assessment targeting `Node.js` infrastructure, a high-severity **Server-Side Request Forgery (SSRF)** vulnerability was identified.

## Target Details & Vulnerability Surface
- **Vulnerability Category**: `ssrf`
- **Target Technology**: `Node.js`
- **Affected Path / Endpoint**: `/api/v1/crawler/extract?link=`
- **Scenario Description**: Web crawler Kubernetes service account token theft

## Attack Vector & Technical Analysis
The target application deployed on `Node.js` exposed `/api/v1/crawler/extract?link=`.
An attacker sends a crafted request exploiting `ssrf` mechanisms.
The backend processing engine fails to enforce authorization boundaries, resulting in security exposure.

## Key Indicators & Extracted Patterns
- **Endpoint Pattern**: `/api/v1/crawler/extract?link=`
- **Vulnerability Types**: `ssrf`
- **Target Tech Stack**: `node.js`
