# Bug Bounty Research Report #160: Mass Assignment / Auto-Binding on Django

## Executive Summary
During an offensive security assessment targeting `Django` infrastructure, a high-severity **Mass Assignment / Auto-Binding** vulnerability was identified.

## Target Details & Vulnerability Surface
- **Vulnerability Category**: `mass_assignment`
- **Target Technology**: `Django`
- **Affected Path / Endpoint**: `/api/v3/orders/create`
- **Scenario Description**: Order creation price override ('price': 0.00)

## Attack Vector & Technical Analysis
The target application deployed on `Django` exposed `/api/v3/orders/create`.
An attacker sends a crafted request exploiting `mass_assignment` mechanisms.
The backend processing engine fails to enforce authorization boundaries, resulting in security exposure.

## Key Indicators & Extracted Patterns
- **Endpoint Pattern**: `/api/v3/orders/create`
- **Vulnerability Types**: `mass_assignment`
- **Target Tech Stack**: `django`
