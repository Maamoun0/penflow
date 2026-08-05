# Bug Bounty Research Report #147: Mass Assignment / Auto-Binding on Express

## Executive Summary
During an offensive security assessment targeting `Express` infrastructure, a high-severity **Mass Assignment / Auto-Binding** vulnerability was identified.

## Target Details & Vulnerability Surface
- **Vulnerability Category**: `mass_assignment`
- **Target Technology**: `Express`
- **Affected Path / Endpoint**: `/api/v1/users/register`
- **Scenario Description**: Registration payload role injection ('role': 'admin')

## Attack Vector & Technical Analysis
The target application deployed on `Express` exposed `/api/v1/users/register`.
An attacker sends a crafted request exploiting `mass_assignment` mechanisms.
The backend processing engine fails to enforce authorization boundaries, resulting in security exposure.

## Key Indicators & Extracted Patterns
- **Endpoint Pattern**: `/api/v1/users/register`
- **Vulnerability Types**: `mass_assignment`
- **Target Tech Stack**: `express`
