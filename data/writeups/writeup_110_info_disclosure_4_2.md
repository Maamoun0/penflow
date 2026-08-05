# Bug Bounty Research Report #110: Information Disclosure & Secret Exposure on Spring Boot

## Executive Summary
During an offensive security assessment targeting `Spring Boot` infrastructure, a high-severity **Information Disclosure & Secret Exposure** vulnerability was identified.

## Target Details & Vulnerability Surface
- **Vulnerability Category**: `info_disclosure`
- **Target Technology**: `Spring Boot`
- **Affected Path / Endpoint**: `/.git/HEAD`
- **Scenario Description**: Exposed Git repository metadata enabling source code reconstruction

## Attack Vector & Technical Analysis
The target application deployed on `Spring Boot` exposed `/.git/HEAD`.
An attacker sends a crafted request exploiting `info_disclosure` mechanisms.
The backend processing engine fails to enforce authorization boundaries, resulting in security exposure.

## Key Indicators & Extracted Patterns
- **Endpoint Pattern**: `/.git/HEAD`
- **Vulnerability Types**: `info_disclosure`
- **Target Tech Stack**: `spring boot`
