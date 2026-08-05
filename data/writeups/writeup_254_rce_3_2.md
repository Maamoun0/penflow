# Bug Bounty Research Report #254: Remote Code Execution (RCE) on Spring Boot

## Executive Summary
During an offensive security assessment targeting `Spring Boot` infrastructure, a high-severity **Remote Code Execution (RCE)** vulnerability was identified.

## Target Details & Vulnerability Surface
- **Vulnerability Category**: `rce`
- **Target Technology**: `Spring Boot`
- **Affected Path / Endpoint**: `/api/v1/exec/script?code=`
- **Scenario Description**: Unsanitized eval script execution

## Attack Vector & Technical Analysis
The target application deployed on `Spring Boot` exposed `/api/v1/exec/script?code=`.
An attacker sends a crafted request exploiting `rce` mechanisms.
The backend processing engine fails to enforce authorization boundaries, resulting in security exposure.

## Key Indicators & Extracted Patterns
- **Endpoint Pattern**: `/api/v1/exec/script?code=`
- **Vulnerability Types**: `rce`
- **Target Tech Stack**: `spring boot`
