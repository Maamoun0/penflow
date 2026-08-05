# Spring Boot Actuator Heapdump Exfiltration

## Executive Summary
An exposed Spring Boot Actuator endpoint at `/actuator/heapdump` leaked 2GB of unencrypted process memory.

## Technical Deep Dive
Parsing the `.hprof` binary dump using MAT (Memory Analyzer Tool) extracted live database passwords, AWS secret keys, and active user JWT tokens directly from JVM heap memory.

## Key Indicators & Patterns
- Endpoint: `/actuator/heapdump`
- Vulnerability Type: `info_disclosure`, `actuator`
- Target Tech: `spring`, `java`
