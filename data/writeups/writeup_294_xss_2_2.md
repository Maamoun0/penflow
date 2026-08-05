# Bug Bounty Research Report #294: Cross-Site Scripting (XSS) on Spring Boot

## Executive Summary
During an offensive security assessment targeting `Spring Boot` infrastructure, a high-severity **Cross-Site Scripting (XSS)** vulnerability was identified.

## Target Details & Vulnerability Surface
- **Vulnerability Category**: `xss`
- **Target Technology**: `Spring Boot`
- **Affected Path / Endpoint**: `/api/v1/comments`
- **Scenario Description**: Stored XSS payload stored in rich text editor

## Attack Vector & Technical Analysis
The target application deployed on `Spring Boot` exposed `/api/v1/comments`.
An attacker sends a crafted request exploiting `xss` mechanisms.
The backend processing engine fails to enforce authorization boundaries, resulting in security exposure.

## Key Indicators & Extracted Patterns
- **Endpoint Pattern**: `/api/v1/comments`
- **Vulnerability Types**: `xss`
- **Target Tech Stack**: `spring boot`
