# Research Paper 20: CORS Exploitation via Null Origin Reflection in Sandboxed Iframes

## Summary
Servers configured to accept `Origin: null` for sandboxed iframes or local HTML files allow attackers to trigger cross-origin data extraction using `<iframe sandbox="allow-scripts">`.

## Tactical Patterns
- Target Technology: Modern Web Apps, CORS Headers
- Endpoint Pattern: `/api/v1/user/private-keys`
- Endpoint Pattern: `/api/v1/account/tokens`
- Endpoint Pattern: `/api/v1/profile/data`
- Category: CORS, Information Disclosure
