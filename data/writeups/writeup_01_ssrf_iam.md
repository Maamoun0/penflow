# SSRF to Cloud IAM Credential Theft on Enterprise Infrastructure

## Executive Summary
During a bug bounty assessment on a major cloud target, an unauthenticated SSRF vulnerability was discovered in the PDF export feature at `/api/v1/render/pdf?url=...`.

## Technical Deep Dive
By passing `http://169.254.169.254/latest/meta-data/iam/security-credentials/production-role` as the `url` parameter, the internal headless browser queried AWS IMDS.
The server rendered the returned AWS AccessKeyId, SecretAccessKey, and Token into the generated PDF document.

## Key Indicators & Patterns
- Endpoint: `/api/v1/render/pdf?url=http://169.254.169.254/latest/meta-data/`
- Vulnerability Type: `ssrf`, `info_disclosure`
- Target Tech: `aws`, `node`, `express`
