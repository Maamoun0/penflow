# Research Paper 14: SAML 2.0 XML Signature Wrapping (XSW) & SSO Assertion Takeover

## Summary
Enterprise Identity Providers (IdP) rely on SAML 2.0 assertions. XML Signature Wrapping (XSW) manipulates the XML document structure so that the signature validator checks a legitimate XML element while the application logic evaluates a cloned untrusted element.

## Tactical Patterns
- Target Technology: SAML 2.0, Okta, Shibboleth, Java Enterprise
- Endpoint Pattern: `/api/v1/auth/saml/sso`
- Endpoint Pattern: `/saml/acs/consume`
- Endpoint Pattern: `/api/v1/sso/callback`
- Category: Authentication Bypass, OAuth/JWT
