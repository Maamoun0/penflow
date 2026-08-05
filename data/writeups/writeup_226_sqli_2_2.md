# Bug Bounty Research Report #226: SQL Injection on Spring Boot

## Executive Summary
During an offensive security assessment targeting `Spring Boot` infrastructure, a high-severity **SQL Injection** vulnerability was identified.

## Target Details & Vulnerability Surface
- **Vulnerability Category**: `sqli`
- **Target Technology**: `Spring Boot`
- **Affected Path / Endpoint**: `/api/v2/users?sort=`
- **Scenario Description**: ORDER BY clause blind SQL injection

## Attack Vector & Technical Analysis
The target application deployed on `Spring Boot` exposed `/api/v2/users?sort=`.
An attacker sends a crafted request exploiting `sqli` mechanisms.
The backend processing engine fails to enforce authorization boundaries, resulting in security exposure.

## Key Indicators & Extracted Patterns
- **Endpoint Pattern**: `/api/v2/users?sort=`
- **Vulnerability Types**: `sqli`
- **Target Tech Stack**: `spring boot`
