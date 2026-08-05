# Research Paper 12: Cross-Site WebSocket Hijacking (CSWSH) & Session Compromise

## Executive Summary
HTML5 WebSockets establish persistent bidirectional TCP connections between web clients and backend servers. Unlike standard REST APIs with explicit CORS policies, WebSocket handshakes rely strictly on browser HTTP cookie propagation.

## Tactical Vector Analysis
- Endpoint Pattern: `/ws/v1/chat`
- Endpoint Pattern: `/ws/v1/notifications`
- Endpoint Pattern: `/socket.io`

When backend WebSocket servers fail to validate the HTTP `Origin` header during initial handshake (`GET /ws/v1/chat`), attacker websites can initiate cross-origin WebSocket connections, gaining real-time access to confidential streaming notifications and user chat streams.

## Key Indicators
- Vulnerability Type: WebSocket, CSWSH, Cross-Site Hijacking, Session Leakage
- Targeted Endpoints: `/ws/v1/chat`, `/ws/v1/notifications`, `/socket.io`
- Attack Technique: Origin header validation omission, Cookie session hijacking
