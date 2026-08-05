# Bug Bounty Research Report #261: Rate Limit Bypass on Node.js

## Executive Summary
During an offensive security assessment targeting `Node.js` infrastructure, a high-severity **Rate Limit Bypass** vulnerability was identified.

## Target Details & Vulnerability Surface
- **Vulnerability Category**: `rate_limit`
- **Target Technology**: `Node.js`
- **Affected Path / Endpoint**: `/api/v2/otp/verify`
- **Scenario Description**: Client IP rotation via Client-IP and X-Real-IP headers

## Attack Vector & Technical Analysis
The target application deployed on `Node.js` exposed `/api/v2/otp/verify`.
An attacker sends a crafted request exploiting `rate_limit` mechanisms.
The backend processing engine fails to enforce authorization boundaries, resulting in security exposure.

## Key Indicators & Extracted Patterns
- **Endpoint Pattern**: `/api/v2/otp/verify`
- **Vulnerability Types**: `rate_limit`
- **Target Tech Stack**: `node.js`
