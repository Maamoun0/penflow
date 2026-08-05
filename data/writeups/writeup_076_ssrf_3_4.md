# Bug Bounty Research Report #076: Server-Side Request Forgery (SSRF) on Django

## Executive Summary
During an offensive security assessment targeting `Django` infrastructure, a high-severity **Server-Side Request Forgery (SSRF)** vulnerability was identified.

## Target Details & Vulnerability Surface
- **Vulnerability Category**: `ssrf`
- **Target Technology**: `Django`
- **Affected Path / Endpoint**: `/api/v1/image/proxy?src=`
- **Scenario Description**: Image proxy protocol smuggling file:///etc/passwd

## Attack Vector & Technical Analysis
The target application deployed on `Django` exposed `/api/v1/image/proxy?src=`.
An attacker sends a crafted request exploiting `ssrf` mechanisms.
The backend processing engine fails to enforce authorization boundaries, resulting in security exposure.

## Key Indicators & Extracted Patterns
- **Endpoint Pattern**: `/api/v1/image/proxy?src=`
- **Vulnerability Types**: `ssrf`
- **Target Tech Stack**: `django`
