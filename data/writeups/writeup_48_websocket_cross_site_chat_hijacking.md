# Research Paper 48: Cross-Site WebSocket Hijacking (CSWSH) in Customer Support Live Chat

## Summary
WebSocket handshake endpoints that rely purely on session cookies without anti-CSRF tokens or strict `Origin` header validation allow external malicious websites to initiate WebSocket connections on behalf of the logged-in user. Attackers can eavesdrop on real-time private messages and dispatch spoofed commands.

## Tactical Patterns
- Target Technology: WebSocket, Socket.io, ws, Django Channels
- Endpoint Pattern: `/ws/chat/stream`
- Endpoint Pattern: `/socket.io/?EIO=4`
- Endpoint Pattern: `/live/notifications`
- Category: WebSocket, CSWSH
