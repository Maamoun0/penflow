# Bug Bounty Research Report #237: Server-Side Template Injection (SSTI) on Node.js

## Executive Summary
During an offensive security assessment targeting `Node.js` infrastructure, a high-severity **Server-Side Template Injection (SSTI)** vulnerability was identified.

## Target Details & Vulnerability Surface
- **Vulnerability Category**: `ssti`
- **Target Technology**: `Node.js`
- **Affected Path / Endpoint**: `/api/v2/email/preview?content=`
- **Scenario Description**: Spring Expression Language (SpEL) ${7*7} evaluation

## Attack Vector & Technical Analysis
The target application deployed on `Node.js` exposed `/api/v2/email/preview?content=`.
An attacker sends a crafted request exploiting `ssti` mechanisms.
The backend processing engine fails to enforce authorization boundaries, resulting in security exposure.

## Key Indicators & Extracted Patterns
- **Endpoint Pattern**: `/api/v2/email/preview?content=`
- **Vulnerability Types**: `ssti`
- **Target Tech Stack**: `node.js`
