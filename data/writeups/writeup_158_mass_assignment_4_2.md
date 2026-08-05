# Bug Bounty Research Report #158: Mass Assignment / Auto-Binding on Spring Boot

## Executive Summary
During an offensive security assessment targeting `Spring Boot` infrastructure, a high-severity **Mass Assignment / Auto-Binding** vulnerability was identified.

## Target Details & Vulnerability Surface
- **Vulnerability Category**: `mass_assignment`
- **Target Technology**: `Spring Boot`
- **Affected Path / Endpoint**: `/api/v3/orders/create`
- **Scenario Description**: Order creation price override ('price': 0.00)

## Attack Vector & Technical Analysis
The target application deployed on `Spring Boot` exposed `/api/v3/orders/create`.
An attacker sends a crafted request exploiting `mass_assignment` mechanisms.
The backend processing engine fails to enforce authorization boundaries, resulting in security exposure.

## Key Indicators & Extracted Patterns
- **Endpoint Pattern**: `/api/v3/orders/create`
- **Vulnerability Types**: `mass_assignment`
- **Target Tech Stack**: `spring boot`
