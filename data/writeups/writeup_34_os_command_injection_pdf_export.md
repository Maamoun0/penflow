# Research Paper 34: OS Command Injection in PDF Generator Microservice

## Summary
Backend services invoking command-line utilities (such as wkhtmltopdf or ffmpeg) via system shell functions without strict argument quoting permit OS command injection. Injecting pipe characters (`|`) or command substitution (`$(id)`) executes commands with the web server process permissions.

## Tactical Patterns
- Target Technology: Node.js child_process, Python os.system, wkhtmltopdf
- Endpoint Pattern: `/api/v1/export/pdf`
- Endpoint Pattern: `/api/v1/media/convert`
- Endpoint Pattern: `/api/v1/tools/ping`
- Category: RCE, OS Command Injection
