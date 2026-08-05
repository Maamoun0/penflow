# PenFlow Engineering Constitution (PEC v1.0)
## Master System Authority & Supreme Engineering Charter

**Document Version:** 1.0.0  
**Authority:** Chief Systems Architect, PenFlow Platform  
**Status:** Supreme Engineering Authority  
**Effective Date:** August 4, 2026  
**Target Audience:** All Engineering Personnel, Platform Contributors, Systems Architects  

---

## SECTION 1: Project Mission

### 1.1 Mission Statement
The mission of PenFlow is to provide an autonomous, self-learning, high-precision security research platform that replicates the cognitive rigor, hypotheses testing, and empirical verification of a world-class penetration testing team. PenFlow systematically discovers high-value, deep logical vulnerabilities across complex software attack surfaces without reliance on brute-force scanning or noisy, un-brokered payload injection.

### 1.2 Problems Solved
- **Noise and Low Signal:** Replaces traditional signature-based scanners that generate massive false positives with an adversarial falsification pipeline that verifies every candidate finding before human delivery.
- **Context Blindness:** Solves the inability of automated tools to comprehend multi-tenant authorization boundaries, stateful business logic workflows, and API object relationships.
- **Knowledge Loss:** Converts historic research, published writeups, execution failures, and human corrections into persistent, structured, cross-program intelligence.
- **Human Exhaustion:** Automates deep recon, state graph mapping, hypothesis generation, and evidence aggregation, enabling human security researchers to focus exclusively on final report approval and high-level strategy.

### 1.3 Anti-Mission (What PenFlow Shall NEVER Become)
PenFlow shall NEVER become:
1. A blind, high-volume HTTP endpoint flooding tool or un-targeted parameter fuzzer.
2. A black-box AI wrapper that hallucinates vulnerabilities without deterministic cryptographic proof.
3. An un-auditable, silent execution engine operating without explicit scope boundaries or cryptographic audit chains.
4. A monolithic, tightly-coupled script repository where tools invoke each other via direct, informal memory calls.

---

## SECTION 2: Core Engineering Principles

Every line of code and architectural decision in PenFlow MUST strictly comply with these sixteen core engineering principles:

1. **Determinism:** Given identical inputs, environment states, and network responses, system state evaluation and confidence calculation MUST yield mathematically identical results.
2. **Modularity:** Every subsystem MUST be isolated into distinct, self-contained packages bounded by formal domain interfaces.
3. **Composability:** Complex workflows MUST be composed by linking lightweight, single-purpose agents via standard message channels.
4. **Observability:** System state, message throughput, queue latency, task transitions, and resource consumption MUST be transparently instrumented via structured logs, metrics, and distributed traces.
5. **Reliability:** The platform MUST tolerate transient network faults, target rate limits, and individual worker crashes without losing global execution state or corrupting campaign progress.
6. **Auditability:** Every decision, observation, command, and finding MUST be cryptographically recorded in an immutable, append-only provenance log.
7. **Extensibility:** New capabilities, testing teams, and specialized agents MUST be pluggable at runtime without modifying platform core source code.
8. **Security by Design:** All internal communications, data storage, and external target interactions MUST adhere to zero-trust principles, cryptographic verification, and strict least-privilege scoping.
9. **Human-in-the-Loop:** The system MUST present fully verified, structured evidence bundles to the human researcher, leaving final report submission and legal action under human control.
10. **Fail Safe:** Any system fault, timeout, boundary violation, or unhandled exception MUST default the affected component to a safe, closed state without leaking credentials or executing out-of-scope actions.
11. **Offline First:** Local state, knowledge indices, and execution queues MUST be capable of running independently of external cloud APIs or third-party web services.
12. **Cost Awareness:** The system MUST profile and control computational, memory, network bandwidth, and LLM API expenditures per task and per campaign.
13. **Knowledge Reuse:** Historic findings, disproven hypotheses, tech stack heuristics, and research writeups MUST be continuously converted into reusable knowledge rules and experience metrics.
14. **Minimal Coupling:** Inter-component dependencies MUST be zero at the memory layer; components interact exclusively via protocol messages.
15. **Maximum Cohesion:** Subsystems MUST group tightly related functionality into dedicated domain modules with single operational goals.
16. **Testability:** All business logic, confidence algebra, domain transitions, and message schemas MUST be 100% testable via deterministic, isolated automated test suites.

---

## SECTION 3: Architectural Principles

PenFlow enforces seven mandatory architectural patterns across its core infrastructure:

### 3.1 Domain-Driven Design (DDD)
The domain is segregated into explicit Bounded Contexts. Domain models (Dataclasses/Pydantic) define the sole language of the platform. Technical logic MUST NOT leak into domain interfaces.

### 3.2 Event-Driven Architecture (EDA)
State changes are published as immutable domain events to topic-based publish/subscribe channels. Event producers MUST NOT have spatial or temporal knowledge of event consumers.

### 3.3 Hexagonal Architecture (Ports and Adapters)
Core domain logic is completely isolated from external infrastructure, databases, network drivers, and third-party APIs. All external integrations MUST communicate via formal Ports (interfaces) implemented by Adapters.

### 3.4 Command Query Responsibility Segregation (CQRS)
State-mutating operations (Commands) are strictly separated from state-reading operations (Queries). Data read models (Target Memory Graphs) are optimized for retrieval, while Command models handle deterministic state validation.

### 3.5 Actor Model Concurrency
Agents operate as isolated Actors with private working memory, an incoming message queue, and independent event-driven execution loops. Shared mutable state across thread or process boundaries is strictly forbidden.

### 3.6 Capability-Based Design
Tasks are dispatched to workers based on abstract capability declarations (`capability="id_access_analysis"`) registered in a global Capability Registry, rather than direct references to specific agent class implementations.

### 3.7 Finite State Machines & Immutable Messages
All tasks, findings, and target workflows follow non-reversible, deterministic state machine transitions. Messages circulating on the wire are strictly immutable.

---

## SECTION 4: Agent Principles

Every Agent deployed inside PenFlow MUST satisfy the following operational invariants:

1. **Single Responsibility:** An agent MUST fulfill exactly one specialized capability.
2. **Capability Exposure:** An agent MUST advertise its supported capabilities, schema versions, and cost metrics to the Capability Registry upon startup.
3. **Zero Direct Calls:** An agent MUST NEVER invoke another agent directly via in-memory calls or private APIs.
4. **Protocol Strictness:** An agent MUST communicate exclusively via standard ACP v1.0 message envelopes routed through verified buses.
5. **Independent Testability:** An agent MUST be testable in complete isolation using mock ACP message streams.
6. **Replaceability & Versioning:** Any agent MUST be hot-swappable with a newer or alternative implementation offering the same capability and semantic versioning contract.
7. **Observability:** An agent MUST propagate OpenTelemetry context headers and emit structured telemetry for all active operations.
8. **Stateless Core Execution:** Agents MUST store operational state in the shared Memory Layer, remaining stateless across task restarts.
9. **Graceful Shutdown & Resilience:** Agents MUST trap SIGTERM/SIGINT signals, flush active working memory logs, release locked resources, and support retries, cancellation commands, and progress reporting.
10. **Structured Reasoning & Confidence:** Agents MUST emit structured reasoning chains and mathematical confidence estimates for all produced results.

---

## SECTION 5: Knowledge Principles

Knowledge in PenFlow represents universal, target-independent security concepts, techniques, playbooks, and research.

- **Immutable Versioning:** Knowledge entries MUST be immutable and versioned using semantic hashes.
- **Traceability & Source Attribution:** Every knowledge rule MUST reference its source origin (e.g., HackerOne Report ID, Academic Paper DOI, PortSwigger URL).
- **Auditability:** Modifications or additions to the Knowledge Base MUST pass automated schema validation and preserve an unbroken audit chain.
- **Confidence Scoring:** Knowledge patterns MUST maintain empirical confidence scores that update based on platform execution outcomes.
- **No Silent Mutations:** Knowledge MUST NEVER be modified silently during scan execution; updates MUST occur through explicit KnowledgeUpdate ACP events.

---

## SECTION 6: Learning Principles

PenFlow enforces a multi-tier learning framework that continuously converts raw outcomes into actionable platform intelligence:

```
[Writeups / Reports / Experiments]
               │
               ▼
   Technique & Pattern Extraction
               │
               ▼
    Hypothesis Generation Rules
               │
               ▼
[Scan Execution & Validation Check]
       │                 │
       ▼                 ▼
[Success Outcome]   [Failure / False Positive]
       │                 │
       └────────┬────────┘
                │
                ▼
   Experience Layer Update
(Success/Failure Rates per Tech Stack)
                │
                ▼
  Dynamic Planner Heuristics Optimization
```

- **Experience:** Cross-program statistical heuristics tracking technique success and failure rates against specific technology stacks.
- **Technique:** A concrete, step-by-step testing mechanism (e.g., JWT Algorithm Confusion).
- **Pattern:** A contextual rule indicating a high probability of a vulnerability (e.g., `/api/v1/users/{id}` + Bearer Token).
- **Writeup & Root Cause:** External vulnerability reports parsed into structural preconditions and failure modes.
- **Feedback Loop:** When a Validation Agent confirms or rejects a candidate finding, the Experience Layer updates the historical success rating of the underlying technique, directly influencing future Planner task prioritization.

---

## SECTION 7: Security Principles

The PenFlow platform operates under a Zero-Trust internal security architecture:

1. **Message Signing:** All ACP messages MUST be signed using HMAC-SHA256 tokens generated by the internal security authority.
2. **Plugin & Agent Trust:** External plugins and third-party agents MUST run inside isolated sandbox containers with zero access to host system environment variables or raw socket controls.
3. **Secrets Handling:** Target credentials, API keys, and session tokens MUST be stored encrypted at rest (AES-GCM-256) and passed to worker agents strictly via ephemeral, in-memory context envelopes.
4. **Supply Chain & Integrity:** All third-party Python dependencies MUST be pinned via hash-locked lockfiles (`requirements.txt` / `uv.lock`) and scanned for known vulnerabilities before deployment.
5. **Least Privilege Routing:** Event Bus topic access MUST enforce Role-Based Access Control (RBAC); specialized testing agents CANNOT publish to administrative or reporting channels.

---

## SECTION 8: Testing Constitution

No feature, capability, or bug fix may be merged into PenFlow without passing the mandatory Testing Pyramid:

```
                      / \
                     /   \
                    / E2E \           (Full Swarm Campaigns)
                   /-------\
                  / System  \         (Multi-Agent DAG Runs)
                 /-----------\
                / Integration \       (ACP Bus & Memory Checks)
               /---------------\
              / Contract & Prop \     (PDS Schemas & Hypothesis Algebra)
             /-------------------\
            /      Unit Tests      \  (Isolated Functions & Models)
           /-------------------------\
```

### 8.1 Mandatory Testing Requirements
- **Unit Tests:** 100% test coverage for domain models, ACP message validation, and utility functions.
- **Property-Based Tests:** Property testing for confidence score algebra, URL normalization, and diff algorithms.
- **Contract Tests:** Strict verification of ACP message schemas and Capability Registry inputs/outputs.
- **Integration Tests:** Bus routing, SQLite Quad-Memory persistence, and HTTP client session swapping.
- **System & E2E Tests:** End-to-end multi-agent execution against mock vulnerability targets (Juice Shop / PortSwigger labs).
- **Mutation & Regression Testing:** Mutation testing runs to verify test suite strength; regression tests required for every reported bug.
- **Zero-Bypass Rule:** Pull requests bypassing automated test execution MUST be automatically rejected.

---

## SECTION 9: Performance Principles & Resource Budgets

PenFlow enforces strict compute and network resource boundaries:

- **CPU & Concurrency:** Worker pools MUST bound asynchronous task concurrency to prevent thread starvation (`max_concurrency` defaults to 10 * CPU cores).
- **RAM Limits:** In-memory HTTP cache and object state memory MUST NOT exceed 2.0 GB per worker process; memory leaks trigger automated worker recycling.
- **Network & Rate Limits:** Network clients MUST observe adaptive rate limits, respects target `robots.txt` / program scope boundaries, and back off on HTTP 429/503 responses.
- **LLM API Budgeting:** High-cost Cloud LLM calls (Gemini/Claude) MUST be gated by the Economy Agent. Routine parsing and summarization MUST execute on local LLMs or regex engines.

---

## SECTION 10: Artificial Intelligence Principles

Artificial Intelligence in PenFlow is strictly governed by deterministic boundaries:

1. **AI as Advisor, Not Authority:** AI models serve exclusively as hypothesis generators, writeup analyzers, and evidence summarizers. AI IS NEVER THE SOURCE OF TRUTH.
2. **Deterministic Precedence:** Deterministic code rules, cryptographic hashes, and HTTP response comparison logic ALWAYS override AI outputs.
3. **Verifiable AI Outputs:** Every decision or candidate finding suggested by an LLM MUST be independently validated by a deterministic testing module or Critic Agent.
4. **Versioning:** Prompts and LLM model identifiers MUST be strictly version-controlled (`prompt_version="1.2.0"`, `model="gemini-3.6-flash"`).
5. **Fallback Strategy:** If Cloud LLM APIs become unavailable or exceed cost budgets, the platform MUST fallback to local Ollama LLMs or rule-based heuristics seamlessly.

---

## SECTION 11: Evolution Principles

The platform is designed to evolve continuously across years of operation without structural breakage:

- **Semantic Versioning:** Platform releases follow `MAJOR.MINOR.PATCH` versioning.
- **Deprecation Windows:** Deprecated capabilities, message fields, or API endpoints require a minimum two MAJOR version deprecation notice before removal.
- **Schema Evolution:** All ACP message envelopes MUST use forward-compatible parsers that ignore unrecognized fields.
- **Database Migrations:** Database schema alterations MUST be managed via automated, non-destructive migration scripts.

---

## SECTION 12: Coding Constitution

All PenFlow source code MUST adhere to strict software craftsmanship rules:

1. **Folder Ownership:** Subsystems MUST respect package ownership boundaries (`penflow/core`, `penflow/domain`, `penflow/agents`, `penflow/memory`).
2. **Naming Conventions:** Python modules use `snake_case`; Dataclasses and Interfaces use `PascalCase`; Constants use `UPPER_SNAKE_CASE`.
3. **Import Invariants:** Absolute imports mandatory (`from penflow.domain.models import Target`). CIRCULAR IMPORTS ARE STRICTLY FORBIDDEN.
4. **Explicit Interfaces:** Type annotations (`typing`) MANDATORY on all function signatures and class methods.
5. **Error Handling:** Generic `except Exception: pass` blocks are BANNED. Exceptions MUST be explicitly caught, logged with correlation context, and handled safely.
6. **Documentation & Comments:** Code must be self-documenting. Complex algorithmic logic MUST include docstrings explaining intent, inputs, outputs, and edge cases.

---

## SECTION 13: Definition of Done (DoD)

A feature, agent, or capability is certified COMPLETE only when all fourteen conditions are met:

- [ ] 1. Architecture & PDS/ACP compliance verified by System Architect.
- [ ] 2. All Unit, Integration, and Contract tests pass with 100% green status.
- [ ] 3. Documentation updated in `docs/` and inline module docstrings.
- [ ] 4. OpenTelemetry tracing and structured logging context injected.
- [ ] 5. Prometheus operational metrics defined and validated.
- [ ] 6. Resource usage benchmarked within CPU, RAM, and network limits.
- [ ] 7. Internal security review completed (least privilege, input validation).
- [ ] 8. Knowledge Base schemas updated if new techniques are introduced.
- [ ] 9. Capability registered with Capability Registry schema.
- [ ] 10. Audit trail event logging verified for all domain transitions.
- [ ] 11. Fallback strategy verified for LLM or network dependency failures.
- [ ] 12. No circular imports or broken domain boundary violations.
- [ ] 13. Relevant ADR (Architectural Decision Record) updated if architectural shift occurred.
- [ ] 14. Code formatted cleanly adhering to PEP8 and type annotations.

---

## SECTION 14: Non-Goals

To maintain sharp engineering focus, PenFlow explicitly defines what it will NEVER attempt to accomplish:

1. **Not a Generic Web Vulnerability Scanner:** PenFlow will not compete with legacy scanners (e.g. Acunetix, Nikto) for low-hanging, bulk signature matching.
2. **Not an Exploitation Engine:** PenFlow will not generate destructive exploitation payloads, remote code execution shells, or weaponized attack tools.
3. **Not an Unsupervised Auto-Submitter:** PenFlow will never automatically submit reports to HackerOne or Bugcrowd without explicit human review and approval.
4. **Not a Distributed Denial of Service Tool:** PenFlow will not perform high-volume volumetric flooding, brute-force password cracking, or resource exhaustion attacks.

---

## SECTION 15: Future Vision & Four-Platform Hierarchy

To ensure PenFlow scales seamlessly over the next 5+ years without architectural redesign, the platform is structured into four high-level operational platforms:

```
                               PenFlow Master Platform
                                          │
 ┌──────────────────────┬─────────────────┴──────────────────┬──────────────────────┐
 ▼                      ▼                                    ▼                      ▼
PenFlow Core      Security Research                      Automation            Intelligence
 Platform             Platform                            Platform               Platform
 (ACP, Bus,       (Recon, API, Web,                     (Planning, Tasks,      (Writeup Mining,
 Memory, Quad DB)  Cloud, Mobile, Binary)                Critic, Evidence)      Experience Graph)
```

1. **PenFlow Core Platform:** The underlying engine providing ACP messaging, the Task Scheduler, Quad-Memory Engine, Capability Registry, Resource Controller, and Plugin SDK.
2. **Security Research Platform:** The domain testing hub containing Recon Teams, Fingerprinting Teams, API/Web/Cloud/Mobile Analysis Teams, and Binary Research modules.
3. **Automation Platform:** The operational execution engine housing the Planner Agent, Falsification Critic, Evidence Collector, and Human Review Dashboard.
4. **Intelligence Platform:** The continuous learning engine managing Writeup Mining, Payload Intelligence, Technique Graphs, Target Similarity engines, and the Experience Layer.

---

## SECTION 16: Immediate Execution Order Mandate

With the ratification of this Engineering Constitution (PEC v1.0), **ALL HIGH-LEVEL ARCHITECTURAL DESIGN AND SPECIFICATION PHASES ARE OFFICIALLY CONCLUDED.**

To prevent *analysis paralysis*, the engineering team MUST immediately cease document generation and execute development according to the following strict, linear implementation order:

```
Step 1: PenFlow Core Domain Models & Interfaces (penflow/domain/)
  └─► Step 2: ACP v1.0 Event Bus & Command Bus Engine (penflow/core/)
        └─► Step 3: Quad-Memory & Persistence Engine (penflow/memory/)
              └─► Step 4: Capability Registry & Worker Scheduler Engine
                    └─► Step 5: First Specialized Connector (HTTP / Recon Driver)
                          └─► Step 6: First Micro-Agent (Recon Agent)
                                └─► Step 7: First Security Agent (IDOR/BOLA Agent)
                                      └─► Step 8: End-to-End Test Suite Execution
```

---
*By Order of the Chief Systems Architect — PenFlow Engineering Constitution (PEC v1.0)*  
*Ratified & Certified for Immediate Implementation.*
