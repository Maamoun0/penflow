# Bug Bounty Research Report #196: OAuth 2.0 & JWT Security Flaws on Django

## Executive Summary
During an offensive security assessment targeting `Django` infrastructure, a high-severity **OAuth 2.0 & JWT Security Flaws** vulnerability was identified.

## Target Details & Vulnerability Surface
- **Vulnerability Category**: `oauth_jwt`
- **Target Technology**: `Django`
- **Affected Path / Endpoint**: `/api/v1/auth/login`
- **Scenario Description**: JWT algorithm confusion RS256 to HS256 public key signing

## Attack Vector & Technical Analysis
The target application deployed on `Django` exposed `/api/v1/auth/login`.
An attacker sends a crafted request exploiting `oauth_jwt` mechanisms.
The backend processing engine fails to enforce authorization boundaries, resulting in security exposure.

## Key Indicators & Extracted Patterns
- **Endpoint Pattern**: `/api/v1/auth/login`
- **Vulnerability Types**: `oauth_jwt`
- **Target Tech Stack**: `django`
