# Research Paper 42: Second-Order IDOR in Async Background PDF Invoice Processing

## Summary
In modern microservice architectures, user requests store unvalidated UUID identifiers in message queues (Kafka, RabbitMQ) for asynchronous processing. While the frontend API validates user ownership, the background worker renders invoices by ID without checking the caller context, enabling second-order unauthorized data retrieval.

## Tactical Patterns
- Target Technology: Celery, Kafka, Node.js Workers, AWS SQS
- Endpoint Pattern: `/api/v1/invoices/generate`
- Endpoint Pattern: `/api/v1/jobs/export-data`
- Endpoint Pattern: `/api/v1/downloads/invoice`
- Category: IDOR, Authorization Flaw
