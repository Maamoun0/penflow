# Bug Bounty Research Report #214: NoSQL & Operator Injection on Spring Boot

## Executive Summary
During an offensive security assessment targeting `Spring Boot` infrastructure, a high-severity **NoSQL & Operator Injection** vulnerability was identified.

## Target Details & Vulnerability Surface
- **Vulnerability Category**: `nosql`
- **Target Technology**: `Spring Boot`
- **Affected Path / Endpoint**: `/api/v2/users/search`
- **Scenario Description**: NoSQL '$ne': null query condition injection

## Attack Vector & Technical Analysis
The target application deployed on `Spring Boot` exposed `/api/v2/users/search`.
An attacker sends a crafted request exploiting `nosql` mechanisms.
The backend processing engine fails to enforce authorization boundaries, resulting in security exposure.

## Key Indicators & Extracted Patterns
- **Endpoint Pattern**: `/api/v2/users/search`
- **Vulnerability Types**: `nosql`
- **Target Tech Stack**: `spring boot`
