# Research Paper 39: Apache FreeMarker SSTI Sandbox Escape via NewObject Built-in

## Summary
FreeMarker template engines rendering user-supplied strings with lenient configuration permit sandbox escapes via built-in constructs such as `?new("freemarker.template.utility.Execute")("id")`. This achieves direct OS command execution on Java application servers.

## Tactical Patterns
- Target Technology: Java, Spring MVC, Apache FreeMarker
- Endpoint Pattern: `/api/v1/newsletter/preview`
- Endpoint Pattern: `/api/v1/custom-reports/render`
- Endpoint Pattern: `/api/v1/templates/test`
- Category: SSTI, Remote Code Execution
