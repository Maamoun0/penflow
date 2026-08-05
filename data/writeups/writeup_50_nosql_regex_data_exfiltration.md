# Research Paper 50: Character-by-Character NoSQL Regular Expression Data Exfiltration

## Summary
When search APIs evaluate user input using MongoDB `$regex` without limiting execution, an attacker can extract secret API keys or reset tokens character-by-character by supplying regex prefixes (`{"$regex": "^a"}`) and measuring boolean true/false responses or response lengths.

## Tactical Patterns
- Target Technology: Node.js, Express, MongoDB, Mongoose
- Endpoint Pattern: `/api/v1/users/search`
- Endpoint Pattern: `/api/v1/keys/verify`
- Endpoint Pattern: `/api/v1/tokens/validate`
- Category: NoSQL Injection, Information Disclosure
