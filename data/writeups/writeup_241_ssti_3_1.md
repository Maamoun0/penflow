# Bug Bounty Research Report #241: Server-Side Template Injection (SSTI) on Node.js

## Executive Summary
During an offensive security assessment targeting `Node.js` infrastructure, a high-severity **Server-Side Template Injection (SSTI)** vulnerability was identified.

## Target Details & Vulnerability Surface
- **Vulnerability Category**: `ssti`
- **Target Technology**: `Node.js`
- **Affected Path / Endpoint**: `/api/v1/pdf/generate?template=`
- **Scenario Description**: FreeMarker Java template execute utility execution

## Attack Vector & Technical Analysis
The target application deployed on `Node.js` exposed `/api/v1/pdf/generate?template=`.
An attacker sends a crafted request exploiting `ssti` mechanisms.
The backend processing engine fails to enforce authorization boundaries, resulting in security exposure.

## Key Indicators & Extracted Patterns
- **Endpoint Pattern**: `/api/v1/pdf/generate?template=`
- **Vulnerability Types**: `ssti`
- **Target Tech Stack**: `node.js`
