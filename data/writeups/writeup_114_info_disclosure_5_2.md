# Bug Bounty Research Report #114: Information Disclosure & Secret Exposure on Spring Boot

## Executive Summary
During an offensive security assessment targeting `Spring Boot` infrastructure, a high-severity **Information Disclosure & Secret Exposure** vulnerability was identified.

## Target Details & Vulnerability Surface
- **Vulnerability Category**: `info_disclosure`
- **Target Technology**: `Spring Boot`
- **Affected Path / Endpoint**: `/_profiler/phpinfo`
- **Scenario Description**: Symfony Profiler PHP info environment leak

## Attack Vector & Technical Analysis
The target application deployed on `Spring Boot` exposed `/_profiler/phpinfo`.
An attacker sends a crafted request exploiting `info_disclosure` mechanisms.
The backend processing engine fails to enforce authorization boundaries, resulting in security exposure.

## Key Indicators & Extracted Patterns
- **Endpoint Pattern**: `/_profiler/phpinfo`
- **Vulnerability Types**: `info_disclosure`
- **Target Tech Stack**: `spring boot`
