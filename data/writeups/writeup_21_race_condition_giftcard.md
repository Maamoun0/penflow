# Research Paper 21: Financial Race Condition in Multi-Threaded Gift Card Redemptions

## Summary
Simultaneous redemption of single-use promo codes across concurrent worker threads bypasses balance updates due to improper row locking in relational databases.

## Tactical Patterns
- Target Technology: E-Commerce APIs, PostgreSQL, MySQL
- Endpoint Pattern: `/api/v1/giftcards/apply`
- Endpoint Pattern: `/api/v1/promo/redeem`
- Endpoint Pattern: `/api/v1/checkout/discount`
- Category: Race Condition, TOCTOU
