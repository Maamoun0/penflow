# Bug Bounty Research Report #068: Server-Side Request Forgery (SSRF) on Django

## Executive Summary
During an offensive security assessment targeting `Django` infrastructure, a high-severity **Server-Side Request Forgery (SSRF)** vulnerability was identified.

## Target Details & Vulnerability Surface
- **Vulnerability Category**: `ssrf`
- **Target Technology**: `Django`
- **Affected Path / Endpoint**: `/api/v1/render/pdf?url=`
- **Scenario Description**: Headless Chrome IMDSv1 169.254.169.254 metadata exfiltration

## Attack Vector & Technical Analysis
The target application deployed on `Django` exposed `/api/v1/render/pdf?url=`.
An attacker sends a crafted request exploiting `ssrf` mechanisms.
The backend processing engine fails to enforce authorization boundaries, resulting in security exposure.

## Key Indicators & Extracted Patterns
- **Endpoint Pattern**: `/api/v1/render/pdf?url=`
- **Vulnerability Types**: `ssrf`
- **Target Tech Stack**: `django`
