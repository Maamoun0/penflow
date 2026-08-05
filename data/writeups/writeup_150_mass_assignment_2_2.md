# Bug Bounty Research Report #150: Mass Assignment / Auto-Binding on Spring Boot

## Executive Summary
During an offensive security assessment targeting `Spring Boot` infrastructure, a high-severity **Mass Assignment / Auto-Binding** vulnerability was identified.

## Target Details & Vulnerability Surface
- **Vulnerability Category**: `mass_assignment`
- **Target Technology**: `Spring Boot`
- **Affected Path / Endpoint**: `/api/v2/user/update`
- **Scenario Description**: Profile update auto-binding ('is_verified': true)

## Attack Vector & Technical Analysis
The target application deployed on `Spring Boot` exposed `/api/v2/user/update`.
An attacker sends a crafted request exploiting `mass_assignment` mechanisms.
The backend processing engine fails to enforce authorization boundaries, resulting in security exposure.

## Key Indicators & Extracted Patterns
- **Endpoint Pattern**: `/api/v2/user/update`
- **Vulnerability Types**: `mass_assignment`
- **Target Tech Stack**: `spring boot`
