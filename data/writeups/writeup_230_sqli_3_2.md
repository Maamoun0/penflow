# Bug Bounty Research Report #230: SQL Injection on Spring Boot

## Executive Summary
During an offensive security assessment targeting `Spring Boot` infrastructure, a high-severity **SQL Injection** vulnerability was identified.

## Target Details & Vulnerability Surface
- **Vulnerability Category**: `sqli`
- **Target Technology**: `Spring Boot`
- **Affected Path / Endpoint**: `/api/v1/orders?id=`
- **Scenario Description**: Time-based blind SQL injection (PG_SLEEP / WAITFOR DELAY)

## Attack Vector & Technical Analysis
The target application deployed on `Spring Boot` exposed `/api/v1/orders?id=`.
An attacker sends a crafted request exploiting `sqli` mechanisms.
The backend processing engine fails to enforce authorization boundaries, resulting in security exposure.

## Key Indicators & Extracted Patterns
- **Endpoint Pattern**: `/api/v1/orders?id=`
- **Vulnerability Types**: `sqli`
- **Target Tech Stack**: `spring boot`
