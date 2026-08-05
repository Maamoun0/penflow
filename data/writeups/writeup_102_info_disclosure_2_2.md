# Bug Bounty Research Report #102: Information Disclosure & Secret Exposure on Spring Boot

## Executive Summary
During an offensive security assessment targeting `Spring Boot` infrastructure, a high-severity **Information Disclosure & Secret Exposure** vulnerability was identified.

## Target Details & Vulnerability Surface
- **Vulnerability Category**: `info_disclosure`
- **Target Technology**: `Spring Boot`
- **Affected Path / Endpoint**: `/actuator/env`
- **Scenario Description**: Spring Boot Actuator environment properties exposure

## Attack Vector & Technical Analysis
The target application deployed on `Spring Boot` exposed `/actuator/env`.
An attacker sends a crafted request exploiting `info_disclosure` mechanisms.
The backend processing engine fails to enforce authorization boundaries, resulting in security exposure.

## Key Indicators & Extracted Patterns
- **Endpoint Pattern**: `/actuator/env`
- **Vulnerability Types**: `info_disclosure`
- **Target Tech Stack**: `spring boot`
