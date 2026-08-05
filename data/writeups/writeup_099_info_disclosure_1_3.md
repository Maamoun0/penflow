# Bug Bounty Research Report #099: Information Disclosure & Secret Exposure on Express

## Executive Summary
During an offensive security assessment targeting `Express` infrastructure, a high-severity **Information Disclosure & Secret Exposure** vulnerability was identified.

## Target Details & Vulnerability Surface
- **Vulnerability Category**: `info_disclosure`
- **Target Technology**: `Express`
- **Affected Path / Endpoint**: `/actuator/heapdump`
- **Scenario Description**: Spring Boot Actuator JVM memory heapdump secret leak

## Attack Vector & Technical Analysis
The target application deployed on `Express` exposed `/actuator/heapdump`.
An attacker sends a crafted request exploiting `info_disclosure` mechanisms.
The backend processing engine fails to enforce authorization boundaries, resulting in security exposure.

## Key Indicators & Extracted Patterns
- **Endpoint Pattern**: `/actuator/heapdump`
- **Vulnerability Types**: `info_disclosure`
- **Target Tech Stack**: `express`
