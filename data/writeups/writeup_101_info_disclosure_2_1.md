# Bug Bounty Research Report #101: Information Disclosure & Secret Exposure on Node.js

## Executive Summary
During an offensive security assessment targeting `Node.js` infrastructure, a high-severity **Information Disclosure & Secret Exposure** vulnerability was identified.

## Target Details & Vulnerability Surface
- **Vulnerability Category**: `info_disclosure`
- **Target Technology**: `Node.js`
- **Affected Path / Endpoint**: `/actuator/env`
- **Scenario Description**: Spring Boot Actuator environment properties exposure

## Attack Vector & Technical Analysis
The target application deployed on `Node.js` exposed `/actuator/env`.
An attacker sends a crafted request exploiting `info_disclosure` mechanisms.
The backend processing engine fails to enforce authorization boundaries, resulting in security exposure.

## Key Indicators & Extracted Patterns
- **Endpoint Pattern**: `/actuator/env`
- **Vulnerability Types**: `info_disclosure`
- **Target Tech Stack**: `node.js`
