# Research Paper 03: GraphQL Batching Abuse & Schema Introspection Exfiltration

## Executive Summary
GraphQL APIs introduced performance optimizations like query batching and schema introspection. This paper details how attackers leverage query batching (`[{query:...},{query:...}]`) to amplify brute-force attacks by a factor of 100x while bypassing API rate limiters.

## Tactical Vector Analysis
- Endpoint Pattern: `/graphql`
- Endpoint Pattern: `/api/graphql`
- Endpoint Pattern: `/v1/graphql`

Introspection queries (`__schema { types { fields { name } } }`) expose hidden internal objects, administrative mutations, and unlinked field arguments.

## Key Indicators
- Vulnerability Type: GraphQL Introspection, Query Batching, Information Disclosure
- Targeted Endpoints: `/graphql`, `/api/graphql`, `/v1/graphql`
- Attack Technique: Introspection parsing, Batch query amplification, Object traversal
