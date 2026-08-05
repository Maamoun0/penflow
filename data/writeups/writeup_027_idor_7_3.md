# Bug Bounty Research Report #027: Broken Object Level Authorization (BOLA / IDOR) on Express

## Executive Summary
During an offensive security assessment targeting `Express` infrastructure, a high-severity **Broken Object Level Authorization (BOLA / IDOR)** vulnerability was identified.

## Target Details & Vulnerability Surface
- **Vulnerability Category**: `idor`
- **Target Technology**: `Express`
- **Affected Path / Endpoint**: `/api/v1/tickets/{ticket_id}/attachments`
- **Scenario Description**: Support ticket attachment exfiltration

## Attack Vector & Technical Analysis
The target application deployed on `Express` exposed `/api/v1/tickets/{ticket_id}/attachments`.
An attacker sends a crafted request exploiting `idor` mechanisms.
The backend processing engine fails to enforce authorization boundaries, resulting in security exposure.

## Key Indicators & Extracted Patterns
- **Endpoint Pattern**: `/api/v1/tickets/{ticket_id}/attachments`
- **Vulnerability Types**: `idor`
- **Target Tech Stack**: `express`
