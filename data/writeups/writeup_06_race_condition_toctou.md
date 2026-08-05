# Research Paper 06: Concurrency TOCTOU & Race Condition Double-Spend Vulnerabilities

## Executive Summary
Time-of-Check to Time-of-Use (TOCTOU) race conditions occur when state verification and state mutation are not executed atomically inside a database transaction.

## Tactical Vector Analysis
- Endpoint Pattern: `/api/v1/coupon/claim`
- Endpoint Pattern: `/api/v1/wallet/withdraw`
- Endpoint Pattern: `/api/v1/giftcard/redeem`

Executing synchronized parallel asynchronous bursts (`asyncio.gather`) allows multiple single-use coupon redemptions or duplicate wallet balance withdrawals before the server updates the database lock.

## Key Indicators
- Vulnerability Type: Race Condition, TOCTOU, Concurrency
- Targeted Endpoints: `/api/v1/coupon/claim`, `/api/v1/wallet/withdraw`, `/api/v1/giftcard/redeem`
- Attack Technique: Parallel HTTP bursts, Async synchronization
