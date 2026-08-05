# Research Paper 33: Jinja2 Server-Side Template Injection Leading to RCE

## Summary
Applications rendering user-controlled notification templates or invoice previews using Jinja2 without proper sandboxing allow arbitrary Python code execution. By traversing Python class hierarchies via `__mro__` and `__subclasses__`, an attacker invokes `os.popen()` to gain a remote shell.

## Tactical Patterns
- Target Technology: Python, Flask, Jinja2
- Endpoint Pattern: `/api/v1/templates/preview`
- Endpoint Pattern: `/api/v1/emails/render`
- Endpoint Pattern: `/api/v1/invoices/custom_view`
- Category: SSTI, Remote Code Execution
