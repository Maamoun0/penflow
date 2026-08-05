# Bug Bounty Research Report #156: Mass Assignment / Auto-Binding on Django

## Executive Summary
During an offensive security assessment targeting `Django` infrastructure, a high-severity **Mass Assignment / Auto-Binding** vulnerability was identified.

## Target Details & Vulnerability Surface
- **Vulnerability Category**: `mass_assignment`
- **Target Technology**: `Django`
- **Affected Path / Endpoint**: `/api/v1/account/settings`
- **Scenario Description**: Account settings mass assignment ('plan': 'enterprise')

## Attack Vector & Technical Analysis
The target application deployed on `Django` exposed `/api/v1/account/settings`.
An attacker sends a crafted request exploiting `mass_assignment` mechanisms.
The backend processing engine fails to enforce authorization boundaries, resulting in security exposure.

## Key Indicators & Extracted Patterns
- **Endpoint Pattern**: `/api/v1/account/settings`
- **Vulnerability Types**: `mass_assignment`
- **Target Tech Stack**: `django`
