# Research Paper 17: SSRF Blacklist Bypass via Time-of-Check DNS Rebinding

## Summary
SSRF filters often perform a DNS lookup at validation time to check if an IP is private (127.0.0.1 or 169.254.169.254). DNS Rebinding exploits short TTLs to return a public IP during validation and a private IP during fetch.

## Tactical Patterns
- Target Technology: Python Requests, Node-Fetch, Cloud Services
- Endpoint Pattern: `/api/v1/url/preview`
- Endpoint Pattern: `/api/v1/webhooks/test`
- Endpoint Pattern: `/api/v1/export/pdf`
- Category: SSRF, Cloud Metadata
