# Bug Bounty Research Report #270: Open Redirect on Spring Boot

## Executive Summary
During an offensive security assessment targeting `Spring Boot` infrastructure, a high-severity **Open Redirect** vulnerability was identified.

## Target Details & Vulnerability Surface
- **Vulnerability Category**: `open_redirect`
- **Target Technology**: `Spring Boot`
- **Affected Path / Endpoint**: `/logout?next=`
- **Scenario Description**: Authority @ symbol URL parser confusion trusted.com@evil.com

## Attack Vector & Technical Analysis
The target application deployed on `Spring Boot` exposed `/logout?next=`.
An attacker sends a crafted request exploiting `open_redirect` mechanisms.
The backend processing engine fails to enforce authorization boundaries, resulting in security exposure.

## Key Indicators & Extracted Patterns
- **Endpoint Pattern**: `/logout?next=`
- **Vulnerability Types**: `open_redirect`
- **Target Tech Stack**: `spring boot`
