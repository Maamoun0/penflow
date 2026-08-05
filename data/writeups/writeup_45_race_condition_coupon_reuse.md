# Research Paper 45: Multi-Connection Race Condition in Single-Use Coupon Application

## Summary
E-commerce checkout workflows that check coupon validity before marking the coupon code as redeemed suffer from Time-of-Check to Time-of-Use (TOCTOU) race conditions. Sending 10 concurrent HTTP/2 requests with identical single-use promo codes applies the discount multiple times, reducing cart totals to zero.

## Tactical Patterns
- Target Technology: Node.js, Stripe API, Shopify Custom Apps
- Endpoint Pattern: `/api/v1/cart/apply-coupon`
- Endpoint Pattern: `/api/v1/checkout/redeem`
- Endpoint Pattern: `/api/v1/rewards/claim`
- Category: Race Condition, Business Logic
