# Research Paper 47: Permissive Wildcard Subdomain CORS Policy Coupled with Subdomain Takeover

## Summary
APIs utilizing dynamic CORS validation regexes such as `.*\\.target\\.com` allow any subdomain of `target.com` to make authenticated cross-origin requests with `Access-Control-Allow-Credentials: true`. Chaining this with a dangling CNAME on an abandoned subdomain (`blog.target.com`) enables complete exfiltration of authenticated victim data.

## Tactical Patterns
- Target Technology: CORS, NGINX, Express-cors
- Endpoint Pattern: `/api/v1/user/private-data`
- Endpoint Pattern: `/api/v1/messages/inbox`
- Endpoint Pattern: `/api/v1/account/billing`
- Category: CORS, Origin Reflection
