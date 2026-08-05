# Research Paper 15: GraphQL Recursive Nested Depth Resource Exhaustion

## Summary
GraphQL queries support circular relationships (e.g., User -> Posts -> Author -> Posts). Unrestricted query depth allows attackers to submit deeply nested queries that exhaust server CPU and memory allocations.

## Tactical Patterns
- Target Technology: GraphQL, Apollo Server, Hasura
- Endpoint Pattern: `/api/v2/graphql`
- Endpoint Pattern: `/graphql/v1`
- Endpoint Pattern: `/query/graphql`
- Category: GraphQL, Denial of Service
