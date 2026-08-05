# Bug Bounty Research Report #231: SQL Injection on Express

## Executive Summary
During an offensive security assessment targeting `Express` infrastructure, a high-severity **SQL Injection** vulnerability was identified.

## Target Details & Vulnerability Surface
- **Vulnerability Category**: `sqli`
- **Target Technology**: `Express`
- **Affected Path / Endpoint**: `/api/v1/orders?id=`
- **Scenario Description**: Time-based blind SQL injection (PG_SLEEP / WAITFOR DELAY)

## Attack Vector & Technical Analysis
The target application deployed on `Express` exposed `/api/v1/orders?id=`.
An attacker sends a crafted request exploiting `sqli` mechanisms.
The backend processing engine fails to enforce authorization boundaries, resulting in security exposure.

## Key Indicators & Extracted Patterns
- **Endpoint Pattern**: `/api/v1/orders?id=`
- **Vulnerability Types**: `sqli`
- **Target Tech Stack**: `express`
