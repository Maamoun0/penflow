# Bug Bounty Research Report #222: SQL Injection on Spring Boot

## Executive Summary
During an offensive security assessment targeting `Spring Boot` infrastructure, a high-severity **SQL Injection** vulnerability was identified.

## Target Details & Vulnerability Surface
- **Vulnerability Category**: `sqli`
- **Target Technology**: `Spring Boot`
- **Affected Path / Endpoint**: `/api/v1/products?search=`
- **Scenario Description**: UNION SELECT SQL injection database extraction

## Attack Vector & Technical Analysis
The target application deployed on `Spring Boot` exposed `/api/v1/products?search=`.
An attacker sends a crafted request exploiting `sqli` mechanisms.
The backend processing engine fails to enforce authorization boundaries, resulting in security exposure.

## Key Indicators & Extracted Patterns
- **Endpoint Pattern**: `/api/v1/products?search=`
- **Vulnerability Types**: `sqli`
- **Target Tech Stack**: `spring boot`
