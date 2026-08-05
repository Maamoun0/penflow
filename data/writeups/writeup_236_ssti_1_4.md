# Bug Bounty Research Report #236: Server-Side Template Injection (SSTI) on Django

## Executive Summary
During an offensive security assessment targeting `Django` infrastructure, a high-severity **Server-Side Template Injection (SSTI)** vulnerability was identified.

## Target Details & Vulnerability Surface
- **Vulnerability Category**: `ssti`
- **Target Technology**: `Django`
- **Affected Path / Endpoint**: `/api/v1/template/render?text=`
- **Scenario Description**: Jinja2 Python template injection {{7*'7'}} (7777777)

## Attack Vector & Technical Analysis
The target application deployed on `Django` exposed `/api/v1/template/render?text=`.
An attacker sends a crafted request exploiting `ssti` mechanisms.
The backend processing engine fails to enforce authorization boundaries, resulting in security exposure.

## Key Indicators & Extracted Patterns
- **Endpoint Pattern**: `/api/v1/template/render?text=`
- **Vulnerability Types**: `ssti`
- **Target Tech Stack**: `django`
