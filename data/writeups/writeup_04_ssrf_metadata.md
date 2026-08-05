# Research Paper 04: Server-Side Request Forgery (SSRF) and Cloud Metadata Exfiltration

## Executive Summary
Server-Side Request Forgery occurs when server-side web applications fetch remote URLs specified by clients without validating destination IP addresses.

## Tactical Vector Analysis
- Endpoint Pattern: `/api/v1/webhook/subscribe`
- Endpoint Pattern: `/api/v1/image/fetch`
- Endpoint Pattern: `/api/v1/pdf/render`

Targeting internal link local addresses (`http://169.254.169.254/latest/meta-data/`) allows exfiltration of IAM security credentials, EC2 instance metadata, and internal service bus credentials.

## Key Indicators
- Vulnerability Type: SSRF, Server-Side Request Forgery, Cloud Metadata
- Targeted Endpoints: `/api/v1/webhook/subscribe`, `/api/v1/image/fetch`, `/api/v1/pdf/render`
- Payload Vectors: `169.254.169.254`, `127.0.0.1`, `http://localhost:8080`
