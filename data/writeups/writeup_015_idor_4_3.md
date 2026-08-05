# Bug Bounty Research Report #015: Broken Object Level Authorization (BOLA / IDOR) on Express

## Executive Summary
During an offensive security assessment targeting `Express` infrastructure, a high-severity **Broken Object Level Authorization (BOLA / IDOR)** vulnerability was identified.

## Target Details & Vulnerability Surface
- **Vulnerability Category**: `idor`
- **Target Technology**: `Express`
- **Affected Path / Endpoint**: `/api/v3/documents/{doc_id}/download`
- **Scenario Description**: Document repository authorization bypass

## Attack Vector & Technical Analysis
The target application deployed on `Express` exposed `/api/v3/documents/{doc_id}/download`.
An attacker sends a crafted request exploiting `idor` mechanisms.
The backend processing engine fails to enforce authorization boundaries, resulting in security exposure.

## Key Indicators & Extracted Patterns
- **Endpoint Pattern**: `/api/v3/documents/{doc_id}/download`
- **Vulnerability Types**: `idor`
- **Target Tech Stack**: `express`
