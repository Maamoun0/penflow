# Broken Object Level Authorization (BOLA / IDOR) on Profile Data

## Executive Summary
A critical BOLA vulnerability was identified on the user management endpoint `/api/v2/users/profile?user_id=10842`.

## Technical Deep Dive
By altering the `user_id` query parameter from `10842` to `10843` while retaining User A's Bearer token, the API returned complete PII records of User B.

## Key Indicators & Patterns
- Endpoint: `/api/v2/users/profile?user_id=100`
- Vulnerability Type: `idor`, `bola`, `authorization`
- Target Tech: `rest_api`, `spring`
