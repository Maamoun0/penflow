# Research Paper 13: gRPC-Web Authentication Traversal & Protobuf Deserialization

## Summary
In modern microservice architectures utilizing gRPC-Web over HTTP/2, reverse proxies decode gRPC frames into standard REST calls. Improper authentication checks on internal Protobuf message fields allow unauthenticated callers to invoke internal management RPCs.

## Tactical Patterns
- Target Technology: gRPC-Web, Protocol Buffers, Go, Envoy Proxy
- Endpoint Pattern: `/grpc.v1.UserManagementService/GetUser`
- Endpoint Pattern: `/grpc.v1.AdminService/PurgeAuditLogs`
- Endpoint Pattern: `/grpc.v1.BillingService/UpdateSubscription`
- Category: BFLA, Authorization Bypass
