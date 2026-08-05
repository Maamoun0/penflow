# Bug Bounty Research Report #225: SQL Injection on Node.js

## Executive Summary
During an offensive security assessment targeting `Node.js` infrastructure, a high-severity **SQL Injection** vulnerability was identified.

## Target Details & Vulnerability Surface
- **Vulnerability Category**: `sqli`
- **Target Technology**: `Node.js`
- **Affected Path / Endpoint**: `/api/v2/users?sort=`
- **Scenario Description**: ORDER BY clause blind SQL injection

## Attack Vector & Technical Analysis
The target application deployed on `Node.js` exposed `/api/v2/users?sort=`.
An attacker sends a crafted request exploiting `sqli` mechanisms.
The backend processing engine fails to enforce authorization boundaries, resulting in security exposure.

## Key Indicators & Extracted Patterns
- **Endpoint Pattern**: `/api/v2/users?sort=`
- **Vulnerability Types**: `sqli`
- **Target Tech Stack**: `node.js`
