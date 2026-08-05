# Bug Bounty Research Report #146: Mass Assignment / Auto-Binding on Spring Boot

## Executive Summary
During an offensive security assessment targeting `Spring Boot` infrastructure, a high-severity **Mass Assignment / Auto-Binding** vulnerability was identified.

## Target Details & Vulnerability Surface
- **Vulnerability Category**: `mass_assignment`
- **Target Technology**: `Spring Boot`
- **Affected Path / Endpoint**: `/api/v1/users/register`
- **Scenario Description**: Registration payload role injection ('role': 'admin')

## Attack Vector & Technical Analysis
The target application deployed on `Spring Boot` exposed `/api/v1/users/register`.
An attacker sends a crafted request exploiting `mass_assignment` mechanisms.
The backend processing engine fails to enforce authorization boundaries, resulting in security exposure.

## Key Indicators & Extracted Patterns
- **Endpoint Pattern**: `/api/v1/users/register`
- **Vulnerability Types**: `mass_assignment`
- **Target Tech Stack**: `spring boot`
