# Research Paper 08: API Gateway & WAF Access Control Header Bypass

## Executive Summary
Reverse proxy architectures (such as NGINX, HAProxy, and Envoy) often enforce path-based access control rules before forwarding requests to backend API services. Discrepancies between proxy path parsing and backend routing enable authorization bypasses.

## Tactical Vector Analysis
- Endpoint Pattern: `/api/v1/internal/health`
- Endpoint Pattern: `/api/v1/admin/config`
- Endpoint Pattern: `/api/v1/management/metrics`

By supplying override headers (`X-Original-URL: /api/v1/admin/config` or `X-Rewrite-URL: /api/v1/admin/config`) or appending path matrix parameters (`/api/v1/public/..;/admin/config`), the WAF evaluates the request as public while the backend router executes the administrative endpoint.

## Key Indicators
- Vulnerability Type: WAF Bypass, Gateway Bypass, Authorization Overrides
- Targeted Endpoints: `/api/v1/internal/health`, `/api/v1/admin/config`, `/api/v1/management/metrics`
- Header Vectors: `X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-For`, `X-Custom-IP-Authorization`
