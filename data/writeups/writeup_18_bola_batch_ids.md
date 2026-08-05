# Research Paper 18: BOLA Array Injection in Mass Retrieval APIs

## Summary
API endpoints accepting arrays of IDs (e.g. `{"ids": [101, 102]}`) validate authorization only for the first ID in the array while returning objects for all requested IDs in the response array.

## Tactical Patterns
- Target Technology: Ruby on Rails, Django REST Framework
- Endpoint Pattern: `/api/v1/orders/batch`
- Endpoint Pattern: `/api/v1/messages/bulk`
- Endpoint Pattern: `/api/v1/analytics/export`
- Category: IDOR, BOLA
