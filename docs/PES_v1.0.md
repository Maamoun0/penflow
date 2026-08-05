# PenFlow Engineering Specification (PES v1.0)
## Implementation-Ready Subsystem Specifications for Security Research Operating System (SROS)

**Document Version:** 1.0.0  
**Author:** Lead Systems Engineer, PenFlow Platform  
**Status:** Permanent Implementation Specification  
**Effective Date:** August 4, 2026  
**Target Audience:** Senior Engineering Team, Module Developers, AI Agent Implementers  

---

## EXECUTIVE MANDATE & SYSTEM PARADIGM

PenFlow is specified as a **Security Research Operating System (SROS)**. Under this paradigm:
- The Core Platform functions as the Kernel (managing IPC via ACP, memory isolation, process scheduling, capability routing, and resource budgeting).
- Security Teams, Recon modules, and LLM reasoning engines function as User-Space Applications operating over standardized OS interfaces.
- Third-party CLI tools (e.g., Nuclei, Burp, Semgrep) plug in as Driver Extensions via the Plugin SDK without modifying kernel code.

This document converts the approved architecture and constitution into complete, implementation-ready specifications for every subsystem.

---

## 1. CORE PLATFORM SUBSYSTEM SPECIFICATION

### 1.1 Purpose
Serves as the SROS Kernel runtime host environment, coordinating process lifecycles, memory boundaries, component bootstrapping, and application environment isolation.

### 1.2 Responsibilities
- Bootstraps and orchestrates all platform subsystems.
- Manages application configuration and environment variables.
- Enforces runtime sandboxing and process boundary isolation.
- Manages global shutdown signals and process cleanups.

### 1.3 Functional Requirements
- MUST load configuration schemas from environment variables and JSON configs.
- MUST initialize core subsystems in strict sequential order: Logging -> Security -> EventBus -> Memory -> Scheduler.
- MUST intercept SIGINT/SIGTERM OS signals and initiate graceful teardown.

### 1.4 Non-Functional Requirements
- Kernel boot time MUST NOT exceed 1.5 seconds.
- Memory footprint MUST remain under 150 MB at idle.

### 1.5 Inputs
- Environment environment variables, `config.json` files, CLI flags.

### 1.6 Outputs
- Running platform process context, kernel status events.

### 1.7 Interfaces
- `ICoreKernel`, `IPlatformBootstrapper`, `IConfigLoader`.

### 1.8 Events Consumed
- `SystemShutdownRequested`, `ConfigReloadRequested`.

### 1.9 Events Produced
- `KernelBootstrapped`, `KernelShutdownInitiated`, `KernelShutdownCompleted`.

### 1.10 State Management
- Maintains global kernel runtime status enum: `UNINITIALIZED`, `BOOTSTRAPPING`, `RUNNING`, `TEARDOWN`.

### 1.11 Dependencies
- Python 3.14+ standard library, OS system signals, filesystem access.

### 1.12 Configuration
- `ENV` (development/staging/production), `LOG_LEVEL`, `CONFIG_PATH`.

### 1.13 Security Requirements
- MUST drop elevated OS root/admin privileges after network port binding.
- MUST restrict directory write permissions to designated storage paths.

### 1.14 Reliability Requirements
- 99.99% uptime for core kernel process runtime.

### 1.15 Scalability Requirements
- Supports single-node multi-process execution or multi-container cluster deployments.

### 1.16 Performance Requirements
- Sub-millisecond kernel context dispatching.

### 1.17 Resource Constraints
- Max 200 MB RAM for Kernel core process.

### 1.18 Error Handling
- Fatal kernel bootstrap failures trigger process exit with code 1 and panic log output.

### 1.19 Retry Policy
- Subsystem initialization failures retried up to 3 times before panic shutdown.

### 1.20 Timeout Policy
- Hard 30-second graceful shutdown timeout; un-terminated child processes SIGKILL'd after timeout.

### 1.21 Observability Requirements
- Exposes core uptime metric, memory consumption gauge, and active process tree status.

### 1.22 Logging Requirements
- Structured JSON logging to stdout with `timestamp`, `level`, `component="core_kernel"`.

### 1.23 Metrics
- `penflow_kernel_uptime_seconds`, `penflow_kernel_memory_bytes`.

### 1.24 Audit Requirements
- Cryptographic log block recording kernel boot, configuration hash, and shutdown timestamps.

### 1.25 Testing Requirements
- Unit tests for bootstrapper sequence; integration tests for SIGTERM graceful teardown handling.

### 1.26 Failure Modes
- Missing configuration file -> Immediate boot panic.
- Corrupted memory DB -> Automated rollback to last known good checkpoint.

### 1.27 Acceptance Criteria
- System boots clean, initializes all subsystems in < 1.5s, handles SIGTERM without task corruption, and passes 100% core unit tests.

### 1.28 Future Extension Points
- Dynamic remote configuration fetching via HashiCorp Consul or Kubernetes ConfigMaps.

---

## 2. ACP PROTOCOL ENGINE SPECIFICATION

### 2.1 Purpose
Implements the Agent Communication Protocol (ACP v1.0) messaging engine, providing envelope validation, serialization, deserialization, and cryptographic signing.

### 2.2 Responsibilities
- Constructs and parses ACP v1.0 message envelopes.
- Enforces message schema validation for all message types.
- Signs outgoing messages with HMAC-SHA256 tokens and verifies incoming signatures.
- Rejects expired or replay messages.

### 2.3 Functional Requirements
- MUST validate incoming JSON/Protobuf strings against ACP v1.0 JSON Schemas.
- MUST verify timestamp freshness within a 300-second sliding window.
- MUST verify HMAC-SHA256 payload signature against internal key authority.

### 2.4 Non-Functional Requirements
- Message serialization/deserialization latency MUST NOT exceed 0.5 milliseconds per message.

### 2.5 Inputs
- Raw wire strings (JSON / Protobuf bytes), message payload dicts.

### 2.6 Outputs
- Validated `ACPMessage` domain objects, serialized byte arrays, validation fault exceptions.

### 2.7 Interfaces
- `IACPProtocolEngine`, `IMessageSerializer`, `IMessageSigner`.

### 2.8 Events Consumed
- None (Utility Engine).

### 2.9 Events Produced
- `ACPValidationErrorEmitted`, `ACPReplayAttackDetected`.

### 2.10 State Management
- Maintains in-memory LRU cache of recently processed `message_id` nonces for anti-replay verification.

### 2.11 Dependencies
- `penflow.domain.models`, `json`, `protobuf`, `hmac`, `hashlib`.

### 2.12 Configuration
- `ACP_SIGNING_SECRET`, `MAX_CLOCK_SKEW_SECONDS` (default: 300), `NONCE_CACHE_SIZE` (default: 100000).

### 2.13 Security Requirements
- Secrets MUST NOT be leaked in exception stack traces or validation failure logs.

### 2.14 Reliability Requirements
- 100% deterministic parsing; invalid payloads MUST fail safely without crashing host process.

### 2.15 Scalability Requirements
- Thread-safe, stateless parsing scaling linearly across available CPU worker threads.

### 2.16 Performance Requirements
- Process >= 10,000 message validations per second per core.

### 2.17 Resource Constraints
- Nonce cache memory capped at 50 MB RAM.

### 2.18 Error Handling
- Emits `ACPValidationError` containing specific JSON schema path violation details.

### 2.19 Retry Policy
- Non-retryable parsing errors; immediate message rejection to dead-letter queue.

### 2.20 Timeout Policy
- Validation processing timeout enforced at 100 milliseconds per message.

### 2.21 Observability Requirements
- Exposes validated message counters, error counters, and verification latency histograms.

### 2.22 Logging Requirements
- Log validation failures with `message_id`, `sender`, and validation error code.

### 2.23 Metrics
- `penflow_acp_messages_validated_total`, `penflow_acp_validation_errors_total`, `penflow_acp_processing_latency_seconds`.

### 2.24 Audit Requirements
- All validation fault failures recorded in security audit trail.

### 2.25 Testing Requirements
- Property-based tests for invalid JSON payloads, expired timestamps, and tampered signatures.

### 2.26 Failure Modes
- Invalid HMAC signature -> Message dropped instantly, warning logged.
- Duplicate message ID within freshness window -> Replay attack flag raised.

### 2.27 Acceptance Criteria
- 100% compliance with ACP v1.0 specification schema; passes property testing suite.

### 2.28 Future Extension Points
- Zero-copy binary serialization support using Cap'n Proto or FlatBuffers.

---

## 3. EVENT BUS SUBSYSTEM SPECIFICATION

### 3.1 Purpose
Provides the high-throughput, asynchronous publish/subscribe message backbone for broadcast domain events.

### 3.2 Responsibilities
- Routes published ACP events to registered topic subscribers using exact and wildcard matching (`recon.*`).
- Maintains topic subscriber registries.
- Manages subscriber queue backpressure.

### 3.3 Functional Requirements
- MUST support asynchronous pub/sub routing.
- MUST support topic wildcard matching (`recon.subdomain.*`, `findings.#`).
- MUST deliver events to all registered subscribers for matching topics.

### 3.4 Non-Functional Requirements
- Event routing latency MUST NOT exceed 1.0 millisecond.

### 3.5 Inputs
- Topic string, `ACPMessage` event envelope.

### 3.6 Outputs
- Delivered `ACPMessage` to subscriber queues.

### 3.7 Interfaces
- `IEventBus`, `ITopicRouter`, `ISubscriberRegistry`.

### 3.8 Events Consumed
- All platform domain events.

### 3.9 Events Produced
- `EventBusBufferOverflow`, `SubscriberSlowConsumerWarning`.

### 3.10 State Management
- In-memory subscriber registry mapping topics to async queue handlers.

### 3.11 Dependencies
- `asyncio`, `penflow.core.acp_protocol`.

### 3.12 Configuration
- `EVENT_BUS_QUEUE_SIZE` (default: 10000), `SLOW_CONSUMER_THRESHOLD_MS` (default: 500).

### 3.13 Security Requirements
- Enforces topic publish/subscribe RBAC permissions.

### 3.14 Reliability Requirements
- Isolated subscriber queues; a slow or failing subscriber MUST NOT block delivery to other subscribers.

### 3.15 Scalability Requirements
- Supports 100,000 events/sec across 1,000 active topics.

### 3.16 Performance Requirements
- Lock-free async queue dispatching.

### 3.17 Resource Constraints
- Buffer memory capped at 500 MB.

### 3.18 Error Handling
- Unhandled subscriber exceptions caught and logged without aborting bus loop.

### 3.19 Retry Policy
- Transient queue insertion failures retried 3 times with 10ms delay.

### 3.20 Timeout Policy
- Subscriber delivery timeout 2.0 seconds before slow consumer warning emitted.

### 3.21 Observability Requirements
- Exposes queue depth per topic, total published count, and subscriber processing times.

### 3.22 Logging Requirements
- Log subscriber registration/unregistration and buffer overflow alerts.

### 3.23 Metrics
- `penflow_eventbus_published_total`, `penflow_eventbus_queue_depth`, `penflow_eventbus_dropped_events_total`.

### 3.24 Audit Requirements
- High-priority domain event dispatching recorded in audit log.

### 3.25 Testing Requirements
- Unit tests for wildcard topic matching; integration tests for concurrent multi-subscriber event delivery.

### 3.26 Failure Modes
- Subscriber queue full -> Event dropped to Dead Letter Queue (DLQ), alert raised.

### 3.27 Acceptance Criteria
- Pass all pub/sub routing tests with zero message loss under 10,000 events/sec load.

### 3.28 Future Extension Points
- Plug-in support for distributed message brokers (NATS, Apache Kafka, RabbitMQ).

---

## 4. COMMAND BUS SUBSYSTEM SPECIFICATION

### 4.1 Purpose
Provides deterministic, point-to-point command routing for imperative system actions.

### 4.2 Responsibilities
- Routes command messages to specific target actor addresses.
- Enforces exactly-once execution lock semantics.
- Rejects unauthorized or malformed commands.

### 4.3 Functional Requirements
- MUST route commands directly to the registered handler for `target_actor`.
- MUST enforce Command Lock Registry to prevent duplicate execution of active commands.
- MUST return execution receipt to command issuer.

### 4.4 Non-Functional Requirements
- Command routing latency < 0.5 ms.

### 4.5 Inputs
- Target Actor Address, `ACPMessage` command envelope.

### 4.6 Outputs
- Command Execution Receipt, completion status.

### 4.7 Interfaces
- `ICommandBus`, `ICommandHandlerRegistry`, `ICommandLockRegistry`.

### 4.8 Events Consumed
- `ExecuteCommand`.

### 4.9 Events Produced
- `CommandDispatched`, `CommandRejected`, `CommandCompleted`.

### 4.10 State Management
- Active command lock map (`command_id` -> timestamp).

### 4.11 Dependencies
- `asyncio`, `penflow.core.acp_protocol`.

### 4.12 Configuration
- `COMMAND_TIMEOUT_SECONDS` (default: 30), `MAX_PENDING_COMMANDS` (default: 1000).

### 4.13 Security Requirements
- Command issuer MUST possess administrative execution privileges.

### 4.14 Reliability Requirements
- Exactly-once delivery guarantee.

### 4.15 Scalability Requirements
- 5,000 commands/sec point-to-point dispatching.

### 4.16 Performance Requirements
- Direct pointer/queue dispatching without intermediate topic scanning.

### 4.17 Resource Constraints
- Memory overhead < 50 MB.

### 4.18 Error Handling
- Unhandled command execution errors return formatted `CommandExecutionFault` envelope.

### 4.19 Retry Policy
- Commands are NOT retried automatically unless explicitly flagged with `retryable=true`.

### 4.20 Timeout Policy
- Hard 30-second timeout on command execution acknowledgement.

### 4.21 Observability Requirements
- Exposes pending command depth, dispatch counts, and execution latency gauges.

### 4.22 Logging Requirements
- Log command issuance, execution start, and final result status with correlation IDs.

### 4.23 Metrics
- `penflow_commandbus_dispatched_total`, `penflow_commandbus_execution_latency_seconds`.

### 4.24 Audit Requirements
- 100% of issued commands recorded in immutable audit log.

### 4.25 Testing Requirements
- Unit tests for command locking and duplicate rejection; integration tests for command receipt returns.

### 4.26 Failure Modes
- Target actor unavailable -> Command rejected with `ActorUnreachableFault`.

### 4.27 Acceptance Criteria
- Command locking verified; exactly-once execution proven under concurrency testing.

### 4.28 Future Extension Points
- gRPC remote command execution for distributed worker nodes.

---

## 5. SCHEDULER ENGINE SUBSYSTEM SPECIFICATION

### 5.1 Purpose
Manages task dependencies, resolves Directed Acyclic Graphs (DAGs), and queues ready tasks for execution.

### 5.2 Responsibilities
- Builds, validates, and manages task execution DAGs.
- Evaluates task dependency resolution status.
- Transitions ready tasks from `CREATED` to `SCHEDULED`.
- Triggers cascade cancellations when parent tasks fail.

### 5.3 Functional Requirements
- MUST detect circular dependencies in task DAGs and reject invalid plans.
- MUST hold tasks in `CREATED` state until all `dag_dependencies` achieve `COMPLETED` status.
- MUST immediately transition dependent downstream tasks to `CANCELLED` if a parent task fails.

### 5.4 Non-Functional Requirements
- DAG validation and dependency resolution for 1,000 tasks MUST complete in < 50 milliseconds.

### 5.5 Inputs
- Goal ID, list of `Task` objects defining DAG edges.

### 5.6 Outputs
- Enqueued `SCHEDULED` tasks sent to Worker Scheduler.

### 5.7 Interfaces
- `IDAGScheduler`, `IDependencyResolver`, `ITaskLifecycleManager`.

### 5.8 Events Consumed
- `TaskCompleted`, `TaskFailed`, `TaskCancelled`, `PlanCreated`.

### 5.9 Events Produced
- `TaskScheduled`, `TaskCascadedCancelled`, `DAGCompleted`.

### 5.10 State Management
- In-memory DAG state graph (`plan_id` -> node dependency matrix).

### 5.11 Dependencies
- `networkx` or custom DAG solver, `penflow.domain.models`.

### 5.12 Configuration
- `MAX_DAG_DEPTH` (default: 50), `SCHEDULER_TICK_INTERVAL_MS` (default: 100).

### 5.13 Security Requirements
- Prevents malicious DAG plans from causing infinite evaluation loops.

### 5.14 Reliability Requirements
- State graph persisted to Quad-Memory to support crash recovery.

### 5.15 Scalability Requirements
- Manages up to 500 concurrent active plan DAGs.

### 5.16 Performance Requirements
- $O(V + E)$ topological sort resolution algorithm.

### 5.17 Resource Constraints
- DAG graph memory capped at 200 MB RAM.

### 5.18 Error Handling
- Invalid DAG plans marked `FAILED` with `CircularDependencyFault` details.

### 5.19 Retry Policy
- Scheduler loop retries state updates 3 times on lock contention.

### 5.20 Timeout Policy
- Plan resolution timeout enforced at 5.0 seconds.

### 5.21 Observability Requirements
- Exposes active DAG plan counts, completed task counts, and pending dependency gauges.

### 5.22 Logging Requirements
- Log plan DAG registration, task state transitions, and cascade cancellations.

### 5.23 Metrics
- `penflow_scheduler_active_plans`, `penflow_scheduler_scheduled_tasks_total`, `penflow_scheduler_resolution_seconds`.

### 5.24 Audit Requirements
- All DAG schedule modifications logged to audit trail.

### 5.25 Testing Requirements
- Unit tests for circular DAG detection, topological sorting, and cascade cancellation logic.

### 5.26 Failure Modes
- Parent task failure -> Cascade cancellation sweep executed across all child nodes.

### 5.27 Acceptance Criteria
- Correct topological execution order verified across complex 50-node DAG plans.

### 5.28 Future Extension Points
- Dynamic DAG plan rewriting based on intermediate Recon observations.

---

## 6. WORKER POOL & SCHEDULER SPECIFICATION

### 6.1 Purpose
Manages task worker allocation, execution slots, capability-based worker matching, and preemption.

### 6.2 Responsibilities
- Claims `SCHEDULED` tasks and matches required capabilities via Capability Registry.
- Manages worker process/thread execution slots.
- Monitors task execution heartbeat and enforces hard/soft timeouts.
- Preempts low-priority tasks when high-priority tasks arrive.

### 6.3 Functional Requirements
- MUST query Capability Registry to find optimal worker for task `required_capability`.
- MUST transition task from `SCHEDULED` to `ASSIGNED` upon worker claim, and `RUNNING` on start.
- MUST enforce worker process limits (`max_concurrency`).
- MUST preempt `P3` (LOW) tasks when `P0`/`P1` (CRITICAL/HIGH) tasks require execution slots.

### 6.4 Non-Functional Requirements
- Task assignment latency < 5 milliseconds.

### 6.5 Inputs
- `SCHEDULED` task envelopes.

### 6.6 Outputs
- Task assignment commands to workers, `TaskResult` envelopes.

### 6.7 Interfaces
- `IWorkerPoolManager`, `ITaskDispatcher`, `IPreemptionController`.

### 6.8 Events Consumed
- `TaskScheduled`, `WorkerHeartbeatEmitted`, `WorkerCrashDetected`.

### 6.9 Events Produced
- `TaskAssigned`, `TaskRunning`, `TaskPreempted`, `TaskCompleted`, `TaskFailed`.

### 6.10 State Management
- Active worker slot table (`worker_id` -> {status, active_task_id, start_time, priority}).

### 6.11 Dependencies
- `asyncio`, `multiprocessing`, `penflow.core.capability_registry`.

### 6.12 Configuration
- `MAX_WORKER_CONCURRENCY` (default: 10 * CPU cores), `HEARTBEAT_TIMEOUT_SECONDS` (default: 15).

### 6.13 Security Requirements
- Workers run inside restricted user contexts or isolated containers.

### 6.14 Reliability Requirements
- Orphaned tasks automatically re-queued if worker heartbeat stops for > 15 seconds.

### 6.15 Scalability Requirements
- Scale from 4 local worker slots to 1,000+ distributed container workers.

### 6.16 Performance Requirements
- $O(1)$ worker slot claim logic via async priority queues.

### 6.17 Resource Constraints
- Pool overhead < 100 MB RAM (excluding worker payloads).

### 6.18 Error Handling
- Worker crash triggers worker process restart and task retry evaluation.

### 6.19 Retry Policy
- Failed tasks retried according to task's specific backoff retry policy.

### 6.20 Timeout Policy
- Enforces task `soft_timeout_seconds` (graceful wrap) and `hard_timeout_seconds` (process kill).

### 6.21 Observability Requirements
- Exposes active worker count, slot utilization percentage, preempted task counter.

### 6.22 Logging Requirements
- Log worker assignment, heartbeat timeouts, preemption events, and process crashes.

### 6.23 Metrics
- `penflow_worker_pool_active_workers`, `penflow_worker_pool_utilization_ratio`, `penflow_worker_preemptions_total`.

### 6.24 Audit Requirements
- Worker assignment and preemption history logged to audit trail.

### 6.25 Testing Requirements
- Unit tests for capability matching and preemption; integration tests for worker heartbeat loss recovery.

### 6.26 Failure Modes
- Worker process crash -> Heartbeat monitor detects loss within 15s, marks worker dead, re-queues task.

### 6.27 Acceptance Criteria
- Zero task loss during forced worker process kill testing under load.

### 6.28 Future Extension Points
- Kubernetes Custom Resource Definition (CRD) auto-scaler integration.

---

## 7. CAPABILITY REGISTRY SPECIFICATION

### 7.1 Purpose
Decouples task requirements from concrete agent implementations by providing dynamic capability matching.

### 7.2 Responsibilities
- Registers agent instances, version strings, supported capability strings, and cost factors.
- Resolves the optimal agent instance for a requested capability string.
- Manages agent health check registration.

### 7.3 Functional Requirements
- MUST accept registration payloads containing `agent_id`, `capabilities: List[str]`, `cost_factor: float`, and `version: str`.
- MUST resolve query `findBestAgent(capability)` returning the active agent with lowest cost factor and matching capability.
- MUST unregister agents that fail health check updates.

### 7.4 Non-Functional Requirements
- Capability resolution query latency < 1.0 millisecond.

### 7.5 Inputs
- Agent capability registration envelopes, capability resolution queries.

### 7.6 Outputs
- Selected `agent_id`, capability query result envelopes.

### 7.7 Interfaces
- `ICapabilityRegistry`, `IAgentCapabilityResolver`, `IAgentHealthTracker`.

### 7.8 Events Consumed
- `AgentRegistered`, `AgentHeartbeatEmitted`, `AgentUnregistered`.

### 7.9 Events Produced
- `CapabilityRegistered`, `CapabilityUnregistered`, `NoAgentAvailableFault`.

### 7.10 State Management
- Capability index map (`capability_string` -> List[{agent_id, cost_factor, version, last_seen}]).

### 7.11 Dependencies
- `penflow.domain.models`.

### 7.12 Configuration
- `AGENT_HEALTH_TTL_SECONDS` (default: 30).

### 7.13 Security Requirements
- Agent registration requires valid cryptographic token verification.

### 7.14 Reliability Requirements
- In-memory registry mirrored to SQLite Quad-Memory for crash persistence.

### 7.15 Scalability Requirements
- Indexing 10,000 active capabilities across 1,000 registered agents.

### 7.16 Performance Requirements
- In-memory trie or hash map index search $O(1)$.

### 7.17 Resource Constraints
- Registry memory footprint < 25 MB RAM.

### 7.18 Error Handling
- Unroutable capability query returns `NoCapableAgentAvailableError`.

### 7.19 Retry Policy
- Registry queries retried 3 times with 50ms delay if agent pool is updating.

### 7.20 Timeout Policy
- Capability query resolution timeout 500 milliseconds.

### 7.21 Observability Requirements
- Exposes total registered capabilities count, registered agent count, and resolution failure metrics.

### 7.22 Logging Requirements
- Log capability registration, agent deregistration, and failed resolution queries.

### 7.23 Metrics
- `penflow_capability_registry_agents_total`, `penflow_capability_registry_capabilities_total`, `penflow_capability_queries_failed_total`.

### 7.24 Audit Requirements
- All capability registrations and deregistrations recorded in audit trail.

### 7.25 Testing Requirements
- Unit tests for capability indexing, cost-factor sorting, and TTL health expiry.

### 7.26 Failure Modes
- Requested capability has no active registered agents -> Query fails gracefully with descriptive fault envelope.

### 7.27 Acceptance Criteria
- Correct agent selected based on lowest cost factor across 100 test capability registrations.

### 7.28 Future Extension Points
- Machine-learning driven cost factor weighting based on historic agent performance.

---

## 8. PLUGIN SDK SUBSYSTEM SPECIFICATION

### 8.1 Purpose
Provides the standard, language-agnostic integration SDK for extending PenFlow with custom agents, drivers, and external CLI tool wrappers.

### 8.2 Responsibilities
- Exposes abstract interfaces for Agent lifecycles and messaging.
- Provides standard helper wrappers for ACP serialization, HTTP client sessions, and Quad-Memory interactions.
- Enforces sandbox boundary constraints on plugin execution.

### 8.3 Functional Requirements
- MUST provide base `AbstractAgent` base class implementing the 8-stage lifecycle.
- MUST provide standardized wrapper classes for CLI tools (e.g. Nuclei, Semgrep) translating raw output to `Observation` envelopes.
- MUST sanitize and validate all plugin output against PDS v1.0 domain schemas.

### 8.4 Non-Functional Requirements
- SDK overhead MUST NOT add > 2.0 milliseconds to plugin execution latency.

### 8.5 Inputs
- Plugin configuration dicts, raw CLI outputs, external API responses.

### 8.6 Outputs
- Standardized `ACPMessage` envelopes (`Observation`, `CandidateFinding`).

### 8.7 Interfaces
- `IPluginSDK`, `IAbstractAgent`, `ICLIToolAdapter`, `ISandboxRunner`.

### 8.8 Events Consumed
- Task assignment messages dispatched to the plugin agent.

### 8.9 Events Produced
- Standard ACP events emitted by the plugin agent.

### 8.10 State Management
- Plugin-isolated working memory dictionary.

### 8.11 Dependencies
- `penflow.core.acp_protocol`, `penflow.domain.models`.

### 8.12 Configuration
- `PLUGIN_SANDBOX_ENABLED` (default: true), `PLUGIN_TIMEOUT_DEFAULT` (default: 300).

### 8.13 Security Requirements
- Plugins run under restricted unprivileged OS subprocesses without host shell access (`shell=False`).

### 8.14 Reliability Requirements
- Plugin crashes MUST NOT affect platform core stability.

### 8.15 Scalability Requirements
- Support loading 100+ concurrent third-party plugins.

### 8.16 Performance Requirements
- Zero-copy stream parsing for subprocess stdout/stderr logs.

### 8.17 Resource Constraints
- Subprocess execution capped at configurable CPU and memory limits via OS cgroups/resource module.

### 8.18 Error Handling
- Uncaught plugin exceptions wrapped in `PluginExecutionFault` envelopes.

### 8.19 Retry Policy
- Plugin invocation retried based on task policy settings.

### 8.20 Timeout Policy
- Hard subprocess timeout enforced via OS process tree termination.

### 8.21 Observability Requirements
- Exposes plugin execution duration, invocation count, and fault rate metrics.

### 8.22 Logging Requirements
- Plugin stdout/stderr captured and tagged with `plugin_name` and `task_id`.

### 8.23 Metrics
- `penflow_plugin_executions_total`, `penflow_plugin_faults_total`, `penflow_plugin_duration_seconds`.

### 8.24 Audit Requirements
- Plugin load, execution start, and exit status recorded in audit trail.

### 8.25 Testing Requirements
- Unit tests for `AbstractAgent` base class lifecycle methods; contract tests for CLI tool output parsing.

### 8.26 Failure Modes
- Plugin subprocess hangs -> Subprocess killed on hard timeout, `PluginTimeoutFault` emitted.

### 8.27 Acceptance Criteria
- Custom test plugin successfully loaded, executed inside sandbox, and verified output schema compliance.

### 8.28 Future Extension Points
- WebAssembly (WASM) plugin sandbox execution runner.

---

## 9. OBSERVATION ENGINE SPECIFICATION

### 9.1 Purpose
Captures, normalizes, deduplicates, and indexes raw target telemetry into structured domain `Observation` envelopes.

### 9.2 Responsibilities
- Captures raw HTTP responses, DOM trees, DNS records, TLS certificates, and JavaScript assets.
- Normalizes URLs, headers, and parameter lists into standard PDS formats.
- Computes SHA-256 context hashes to prevent storing duplicate observations.
- Stores normalized observations in the Quad-Memory Engine.

### 9.3 Functional Requirements
- MUST generate unique `observation_id` and SHA-256 content hash for every payload.
- MUST deduplicate identical observations received within a target scan session.
- MUST publish `ObservationCaptured` ACP event upon successful normalization.

### 9.4 Non-Functional Requirements
- Normalization and hashing throughput > 2,000 observations per second per core.

### 9.5 Inputs
- Raw network response dicts, raw text traces, HAR logs.

### 9.6 Outputs
- Normalized `Observation` objects, `ObservationCaptured` events.

### 9.7 Interfaces
- `IObservationEngine`, `ITelemetryNormalizer`, `IDeduplicationIndex`.

### 9.8 Events Consumed
- Raw HTTP response events, crawler output events.

### 9.9 Events Produced
- `ObservationCaptured`, `DuplicateObservationIgnored`.

### 9.10 State Management
- In-memory SHA-256 bloom filter / set for target session deduplication.

### 9.11 Dependencies
- `hashlib`, `urllib.parse`, `penflow.domain.models`.

### 9.12 Configuration
- `DEDUP_CACHE_SIZE` (default: 500000), `ENABLE_RAW_BODY_STORAGE` (default: true).

### 9.13 Security Requirements
- Sensitive authorization tokens scrubbed from raw logs unless explicitly flagged for auth analysis.

### 9.14 Reliability Requirements
- Corrupted observation payloads rejected cleanly without crashing collector queue.

### 9.15 Scalability Requirements
- Scale to process 1,000,000 observations per campaign.

### 9.16 Performance Requirements
- Sub-millisecond hashing and normalization.

### 9.17 Resource Constraints
- Engine RAM < 300 MB.

### 9.18 Error Handling
- Normalization failure moves raw payload to quarantine table for debugging.

### 9.19 Retry Policy
- Non-retryable parsing errors; quarantined immediately.

### 9.20 Timeout Policy
- Processing timeout 500 milliseconds per observation.

### 9.21 Observability Requirements
- Exposes captured observation counters, deduplication ratio, and normalization latency histograms.

### 9.22 Logging Requirements
- Log observation capture summaries, deduplication skips, and parsing errors.

### 9.23 Metrics
- `penflow_observations_captured_total`, `penflow_observations_deduplicated_total`, `penflow_observation_processing_seconds`.

### 9.24 Audit Requirements
- All high-impact observations (e.g. 500 errors, exposed admin panels) logged to audit trail.

### 9.25 Testing Requirements
- Unit tests for URL normalization and SHA-256 deduplication logic; contract tests for HAR log parsing.

### 9.26 Failure Modes
- Malformed HTML/JSON payload -> Normalizer captures raw string, tags payload as `UNPARSED_RAW`.

### 9.27 Acceptance Criteria
- 100% deduplication of identical HTTP responses proven in benchmark testing suite.

### 9.28 Future Extension Points
- Deep DOM AST structural hash comparison for single-page web app deduplication.

---

## 10. KNOWLEDGE ENGINE SPECIFICATION

### 10.1 Purpose
Manages universal, target-independent security knowledge, attack techniques, playbooks, and research repositories.

### 10.2 Responsibilities
- Stores and indexes universal `Knowledge`, `Technique`, `Playbook`, `Research`, and `Pattern` entities.
- Provides vector similarity and semantic search over security writeups and CVE records.
- Manages knowledge pattern versioning and source attribution mapping.

### 10.3 Functional Requirements
- MUST query knowledge base using technique names, tags, or semantic vector queries.
- MUST enforce immutable semantic versioning on all knowledge entries.
- MUST validate that every knowledge entry includes source attribution metadata.

### 10.4 Non-Functional Requirements
- Vector/semantic query retrieval latency < 50 milliseconds.

### 10.5 Inputs
- Knowledge update payloads, research writeup markdowns, query strings.

### 10.6 Outputs
- Matching `Knowledge`, `Technique`, or `Playbook` domain objects.

### 10.7 Interfaces
- `IKnowledgeEngine`, `IKnowledgeRepository`, `IVectorSearchIndex`.

### 10.8 Events Consumed
- `KnowledgeUpdatePublished`, `ResearchWriteupIngested`.

### 10.9 Events Produced
- `KnowledgeBaseUpdated`, `TechniqueIndexed`.

### 10.10 State Management
- SQLite / Vector DB index storing knowledge embeddings and graph nodes.

### 10.11 Dependencies
- `sqlite3` / `sqlite-vec` or local embedding library, `penflow.domain.models`.

### 10.12 Configuration
- `KNOWLEDGE_DB_PATH`, `EMBEDDING_MODEL_NAME` (default: "all-MiniLM-L6-v2").

### 10.13 Security Requirements
- Read-only access for execution worker agents; write access restricted to Knowledge Agent.

### 10.14 Reliability Requirements
- Database file backed up automatically prior to schema migrations.

### 10.15 Scalability Requirements
- Support 100,000 knowledge writeups and 10,000 attack patterns.

### 10.16 Performance Requirements
- In-memory sqlite index cache for high-frequency technique lookups.

### 10.17 Resource Constraints
- Storage footprint < 1.0 GB; RAM footprint < 400 MB.

### 10.18 Error Handling
- Invalid search queries return empty result set with query warning metadata.

### 10.19 Retry Policy
- Database lock retries up to 5 times with exponential backoff.

### 10.20 Timeout Policy
- Query retrieval timeout enforced at 2.0 seconds.

### 10.21 Observability Requirements
- Exposes total knowledge nodes count, query throughput, and vector search latency gauges.

### 10.22 Logging Requirements
- Log knowledge base queries, updates, and indexing operations.

### 10.23 Metrics
- `penflow_knowledge_nodes_total`, `penflow_knowledge_queries_total`, `penflow_knowledge_query_latency_seconds`.

### 10.24 Audit Requirements
- All knowledge additions and pattern version changes recorded in audit log.

### 10.25 Testing Requirements
- Unit tests for knowledge schema validation; integration tests for vector similarity search retrieval.

### 10.26 Failure Modes
- Vector index corruption -> Engine falls back to keyword/tag exact matching queries automatically.

### 10.27 Acceptance Criteria
- Vector query for "JWT header swap" returns correct technique ID within top-3 results.

### 10.28 Future Extension Points
- Graph RAG (Retrieval-Augmented Generation) integration over security knowledge graphs.

---

## 11. LEARNING ENGINE SPECIFICATION

### 11.1 Purpose
Manages the Experience Layer, continuously updating technique success/failure metrics and target similarity heuristics based on real execution outcomes.

### 11.2 Responsibilities
- Processes `FindingVerified` and `FindingRejected` events to calculate empirical technique success rates.
- Updates `ExperiencePattern` metrics for technology stack combinations (e.g. GraphQL + JWT).
- Provides dynamic success probability scores to the Planning Engine to optimize task prioritization.

### 11.3 Functional Requirements
- MUST update `times_tested`, `times_succeeded`, and `success_rate` upon receiving validation events.
- MUST calculate Target Similarity heuristics between historical target tech stacks and new targets.
- MUST adjust technique weight multipliers dynamically based on sample size thresholds ($N \ge 10$).

### 11.4 Non-Functional Requirements
- Experience calculation update latency < 5.0 milliseconds.

### 11.5 Inputs
- `FindingVerified`, `FindingRejected`, `TargetTechStackIdentified` events.

### 11.6 Outputs
- `ExperiencePattern` updates, `TechniqueProbabilityScore` responses to Planner.

### 11.7 Interfaces
- `ILearningEngine`, `IExperienceRepository`, `IHeuristicScorer`.

### 11.8 Events Consumed
- `FindingVerified`, `FindingRejected`, `CandidateSubmitted`.

### 11.9 Events Produced
- `ExperienceUpdated`, `TechniqueRankAdjusted`.

### 11.10 State Management
- Persistence store mapping (`tech_stack_fingerprint` + `technique_id` -> Experience metrics).

### 11.11 Dependencies
- `penflow.domain.models`, `sqlite3`.

### 11.12 Configuration
- `MIN_SAMPLE_THRESHOLD` (default: 10), `DECAY_FACTOR` (default: 0.95 per campaign).

### 11.13 Security Requirements
- Learning metrics MUST NOT leak specific target identifiers or confidential customer data across multi-tenant boundaries.

### 11.14 Reliability Requirements
- Atomic database transactions to ensure metric consistency under parallel event processing.

### 11.15 Scalability Requirements
- Support tracking 1,000,000 execution outcome records across 500 tech stack combinations.

### 11.16 Performance Requirements
- In-memory caching of high-frequency tech stack probability tables.

### 11.17 Resource Constraints
- Engine RAM < 150 MB.

### 11.18 Error Handling
- Out-of-bounds probability calculations capped strictly between 0.0001 and 0.9999.

### 11.19 Retry Policy
- Metric database write locks retried 3 times.

### 11.20 Timeout Policy
- Probability score query timeout 100 milliseconds.

### 11.21 Observability Requirements
- Exposes total experience records, average technique success rates, and learning update counters.

### 11.22 Logging Requirements
- Log technique probability updates, experience updates, and sample size threshold crossings.

### 11.23 Metrics
- `penflow_learning_experience_records_total`, `penflow_learning_updates_total`.

### 11.24 Audit Requirements
- Experience weight modifications logged to audit trail.

### 11.25 Testing Requirements
- Unit tests for success rate calculation algebra; integration tests for feedback loop updates from Critic events.

### 11.26 Failure Modes
- Unrecognized tech stack -> Engine returns baseline universal technique success rate default (0.50).

### 11.27 Acceptance Criteria
- Verified finding correctly increases target technique success rating; rejected candidate decreases rating.

### 11.28 Future Extension Points
- Multi-armed bandit reinforcement learning algorithms for dynamic exploit technique selection.

---

## 12. RECON ENGINE SPECIFICATION

### 12.1 Purpose
Orchestrates target attack surface discovery, subdomain enumeration, port scanning, endpoint extraction, and certificate analysis.

### 12.2 Responsibilities
- Coordinates Subdomain, DNS, HTTP Fingerprint, JS, Certificate, and GitHub Recon agents.
- Enforces scope boundary compliance (in-scope vs out-of-scope targets).
- Normalizes discovered assets into `Asset` and `Endpoint` domain objects.

### 12.3 Functional Requirements
- MUST filter all discovered domain names and IPs against `Target.Scope` rules before emitting.
- MUST publish `AssetDiscovered` and `EndpointDiscovered` ACP events.
- MUST rate-limit external network requests according to target scope guidelines.

### 12.4 Non-Functional Requirements
- Subdomain scope verification latency < 0.1 milliseconds per asset.

### 12.5 Inputs
- `Target` and `Scope` domain objects, raw recon tool stdout logs.

### 12.6 Outputs
- `Asset`, `Endpoint`, and `Observation` domain objects.

### 12.7 Interfaces
- `IReconEngine`, `IScopeVerifier`, `IAssetAggregator`.

### 12.8 Events Consumed
- `TargetScanInitiated`, `ReconTaskAssigned`.

### 12.9 Events Produced
- `ReconIntelPublished`, `AssetDiscovered`, `EndpointDiscovered`, `ScopeViolationBlocked`.

### 12.10 State Management
- Discovered asset tree map (`target_id` -> Set of validated in-scope assets).

### 12.11 Dependencies
- `urllib.parse`, `ipaddress`, `penflow.domain.models`.

### 12.12 Configuration
- `MAX_RECON_PARALLELISM` (default: 20), `SCOPE_STRICT_MODE` (default: true).

### 12.13 Security Requirements
- OUT-OF-SCOPE ASSETS MUST BE BLOCKED IMMEDIATELY BEFORE ANY HTTP INTERACTION.

### 12.14 Reliability Requirements
- Network socket timeouts handled gracefully without aborting overall recon campaign.

### 12.15 Scalability Requirements
- Handle targets with 50,000 subdomains and 500,000 endpoints.

### 12.16 Performance Requirements
- High-performance CIDR block and wildcard domain matching algorithm.

### 12.17 Resource Constraints
- Memory capped at 500 MB RAM for asset tree holding.

### 12.18 Error Handling
- Subdomain resolution failures logged as `DNS_NXDOMAIN` and skipped safely.

### 12.19 Retry Policy
- Transient DNS/HTTP errors retried twice with 1.0s backoff.

### 12.20 Timeout Policy
- Hard timeout 60 seconds per recon tool subprocess.

### 12.21 Observability Requirements
- Exposes total discovered subdomains, active scope blocks, and recon execution durations.

### 12.22 Logging Requirements
- Log asset discoveries, scope block enforcement actions, and tool execution status.

### 12.23 Metrics
- `penflow_recon_assets_discovered_total`, `penflow_recon_scope_violations_blocked_total`.

### 12.24 Audit Requirements
- All scope verification checks logged to audit trail for legal compliance proof.

### 12.25 Testing Requirements
- Unit tests for wildcard domain scope matching (`*.company.com` vs `out.company.com`); property tests for IP CIDR scope checks.

### 12.26 Failure Modes
- Network disconnect -> Recon pauses execution, emits `ReconNetworkPaused` event, retries connectivity check.

### 12.27 Acceptance Criteria
- Out-of-scope domain `evilcompany.com` 100% blocked while `sub.company.com` accepted during test run.

### 12.28 Future Extension Points
- Passive DNS stream integration (SecurityTrails / Shodan API connectors).

---

## 13. FINGERPRINTING ENGINE SPECIFICATION

### 13.1 Purpose
Identifies technologies, frameworks, web servers, programming languages, and API gateways operating on discovered target endpoints.

### 13.2 Responsibilities
- Analyzes HTTP response headers, cookies, HTML meta tags, DOM structures, and JS global variables.
- Maps detected signatures to standardized `Technology` domain entities (e.g. Next.js 14, GraphQL, PostgreSQL).
- Emits technology identification events to update the Target Memory Graph.

### 13.3 Functional Requirements
- MUST match response attributes against signature database containing HTTP headers, body regex, and script paths.
- MUST assign confidence score (0.0 to 1.0) to every identified technology.
- MUST publish `TechnologyIdentified` ACP events upon detection.

### 13.4 Non-Functional Requirements
- Signature matching latency < 2.0 milliseconds per HTTP response.

### 13.5 Inputs
- `Observation` objects containing HTTP response data.

### 13.6 Outputs
- `Technology` domain objects, `TechnologyIdentified` events.

### 13.7 Interfaces
- `IFingerprintingEngine`, `ISignatureMatcher`, `ITechnologyCatalog`.

### 13.8 Events Consumed
- `ObservationCaptured`, `EndpointDiscovered`.

### 13.9 Events Produced
- `TechnologyIdentified`.

### 13.10 State Management
- In-memory signature database loaded from JSON rule files.

### 13.11 Dependencies
- `re`, `json`, `penflow.domain.models`.

### 13.12 Configuration
- `SIGNATURE_DB_PATH`, `MIN_FINGERPRINT_CONFIDENCE` (default: 0.70).

### 13.13 Security Requirements
- Signature regex patterns MUST be protected against Regular Expression Denial of Service (ReDoS) attacks.

### 13.14 Reliability Requirements
- ReDoS-safe regex engine wrapper (e.g., `google/re2` or timeout-bounded regex execution).

### 13.15 Scalability Requirements
- Match 5,000 signature rules against 100,000 HTTP responses per campaign.

### 13.16 Performance Requirements
- Compiled regex patterns initialized at startup.

### 13.17 Resource Constraints
- Signature DB RAM overhead < 50 MB.

### 13.18 Error Handling
- Regex timeout triggers `RegexReDoSSafetyAbort` and skips pattern safely.

### 13.19 Retry Policy
- Non-retryable parsing; skipped on failure.

### 13.20 Timeout Policy
- Regex match execution hard timeout 10 milliseconds per string.

### 13.21 Observability Requirements
- Exposes total identified technologies, signature match counts, and regex processing durations.

### 13.22 Logging Requirements
- Log technology detection results with confidence scores and endpoint IDs.

### 13.23 Metrics
- `penflow_fingerprint_technologies_identified_total`, `penflow_fingerprint_regex_aborts_total`.

### 13.24 Audit Requirements
- Identified technology stack logged to target audit history.

### 13.25 Testing Requirements
- Unit tests for signature matching precision; ReDoS fuzzing tests on all regex patterns.

### 13.26 Failure Modes
- Obfuscated/Server-header stripped response -> Engine falls back to JS global variable and asset hash fingerprinting.

### 13.27 Acceptance Criteria
- 100% accuracy in identifying Next.js, GraphQL, and WAF signatures across test benchmark HTTP dump.

### 13.28 Future Extension Points
- Machine-learning powered HTTP response clustering for unknown framework fingerprinting.

---

## 14. PLANNING ENGINE SPECIFICATION

### 14.1 Purpose
Serves as the strategic brain (CEO / Strategy Director), constructing probabilistic security hypotheses and generating DAG task plans based on target technology graphs and Experience Layer heuristics.

### 14.2 Responsibilities
- Analyzes target technology graph, endpoints, and parameters.
- Queries Experience Layer for historical success probabilities.
- Formulates probabilistic security hypotheses (e.g., `api.company.com` user management API -> 65% BOLA hypothesis).
- Generates DAG task plans and dispatches tasks to Worker Scheduler via ACP.

### 14.3 Functional Requirements
- MUST construct DAG plans where prerequisite tasks (Recon, Auth setup) execute prior to exploit testing tasks.
- MUST prioritize hypotheses using the formula: $PriorityScore = HypothesisProbability \times ExperienceSuccessRate \times ValueMultiplier$.
- MUST update DAG plans dynamically upon receiving preemption triggers or new Recon intel.

### 14.4 Non-Functional Requirements
- Plan generation time for complex 100-endpoint target < 500 milliseconds.

### 14.5 Inputs
- Target state graph (`Target`, `Asset`, `Endpoint`, `Technology`), Experience Layer heuristic scores.

### 14.6 Outputs
- `Plan` and `Task` objects, `HypothesisTaskDispatched` events.

### 14.7 Interfaces
- `IPlanningEngine`, `IHypothesisGenerator`, `IDAGPlanBuilder`.

### 14.8 Events Consumed
- `ReconIntelPublished`, `TechnologyIdentified`, `IntelPreemptionTriggered`, `FindingVerified`.

### 14.9 Events Produced
- `PlanCreated`, `HypothesisTaskDispatched`, `PlanUpdated`, `PlanPreempted`.

### 14.10 State Management
- Active plan registry and hypothesis priority queues in Quad-Memory.

### 14.11 Dependencies
- `penflow.domain.models`, `penflow.core.acp_protocol`.

### 14.12 Configuration
- `MAX_HYPOTHESES_PER_PLAN` (default: 50), `MIN_HYPOTHESIS_SCORE` (default: 0.30).

### 14.13 Security Requirements
- Planning engine CANNOT bypass scope rules or issue tasks against out-of-scope targets.

### 14.14 Reliability Requirements
- Plan state checkpoints saved to SQLite Quad-Memory after every task dispatch.

### 14.15 Scalability Requirements
- Manage plans containing up to 10,000 tasks across complex enterprise attack surfaces.

### 14.16 Performance Requirements
- In-memory priority queue evaluation $O(N \log N)$.

### 14.17 Resource Constraints
- Planning RAM overhead < 300 MB.

### 14.18 Error Handling
- Invalid hypothesis formulation falls back to default baseline vulnerability testing playbook.

### 14.19 Retry Policy
- Planning lock contention retried 3 times.

### 14.20 Timeout Policy
- Plan generation timeout 10.0 seconds.

### 14.21 Observability Requirements
- Exposes generated hypotheses count, active plans count, and task dispatch metrics.

### 14.22 Logging Requirements
- Log hypothesis formulation rationale, priority scores, and DAG plan generation steps.

### 14.23 Metrics
- `penflow_planning_hypotheses_generated_total`, `penflow_planning_plans_created_total`.

### 14.24 Audit Requirements
- All generated plans, hypotheses, and priority scores logged to audit trail.

### 14.25 Testing Requirements
- Unit tests for hypothesis scoring algebra and DAG plan generation; integration tests for dynamic plan updating on new intel.

### 14.26 Failure Modes
- Incomplete target intel -> Planner issues low-level Recon tasks to gather required tech stack context before building exploit plan.

### 14.27 Acceptance Criteria
- Planner correctly prioritizes BOLA hypothesis over generic XSS when target is identified as a multi-role REST API.

### 14.28 Future Extension Points
- Large Language Model (LLM) reasoning integration for multi-step business logic attack path planning.

---

## 15. VALIDATION ENGINE SPECIFICATION

### 15.1 Purpose
Serves as the Adversarial Critic and Falsification Validator, verifying candidate security findings to eliminate false positives prior to human delivery.

### 15.2 Responsibilities
- Receives `Candidate` findings from specialized Security Teams.
- Executes independent re-test requests (Replay checks, differential analysis).
- Applies Confidence Algebra to calculate final confidence scores.
- Promotes candidates with confidence $\ge 0.90$ to `VerifiedFinding`, and rejects candidates with confidence $< 0.50$.

### 15.3 Functional Requirements
- MUST execute independent HTTP replay requests using clean session tokens to verify vulnerability reproducibility.
- MUST compute confidence score using formula: $Confidence = S_{baseline} \times W_{method} \times (1 - D_{deviation}) \times V_{critic}$.
- MUST publish `FindingVerified` if $Confidence \ge 0.90$ or `FindingRejected` if $Confidence < 0.50$.

### 15.4 Non-Functional Requirements
- Validation re-test execution and scoring latency < 3.0 seconds per candidate.

### 15.5 Inputs
- `Candidate` objects containing raw evidence and initial confidence metrics.

### 15.6 Outputs
- `VerifiedFinding`, `Evidence` bundles, `FindingVerified` / `FindingRejected` events.

### 15.7 Interfaces
- `IValidationEngine`, `ICriticValidator`, `IReplayEngine`, `IConfidenceCalculator`.

### 15.8 Events Consumed
- `CandidateFindingSubmitted`.

### 15.9 Events Produced
- `FindingVerified`, `FindingRejected`, `EvidenceBundleCompiled`.

### 15.10 State Management
- Validation workspace storing active replay HTTP traces and diff results.

### 15.11 Dependencies
- `penflow.domain.models`, `penflow.core.acp_protocol`, `httpx`.

### 15.12 Configuration
- `VERIFICATION_CONFIDENCE_THRESHOLD` (default: 0.90), `REJECT_CONFIDENCE_THRESHOLD` (default: 0.50).

### 15.13 Security Requirements
- Validation replay client MUST strictly observe rate limits and scope boundaries.

### 15.14 Reliability Requirements
- Replay tests MUST handle intermittent target timeouts by re-verifying up to 3 times.

### 15.15 Scalability Requirements
- Validate up to 1,000 candidate findings per campaign.

### 15.16 Performance Requirements
- Parallel asynchronous replay execution queues.

### 15.17 Resource Constraints
- RAM overhead < 250 MB.

### 15.18 Error Handling
- Replay connection error drops confidence by deviation penalty, re-queues candidate once.

### 15.19 Retry Policy
- Validation replay retried up to 2 times on transient network drops.

### 15.20 Timeout Policy
- Hard validation timeout 15.0 seconds per candidate finding.

### 15.21 Observability Requirements
- Exposes validated finding count, rejected candidate count, and false positive reduction ratio.

### 15.22 Logging Requirements
- Log candidate verification steps, HTTP response diffs, and final confidence calculations.

### 15.23 Metrics
- `penflow_validation_findings_verified_total`, `penflow_validation_candidates_rejected_total`, `penflow_validation_false_positive_ratio`.

### 15.24 Audit Requirements
- Complete cryptographic evidence bundle and replay trace logged to audit log for verified findings.

### 15.25 Testing Requirements
- Unit tests for Confidence Algebra formula; integration tests for replaying mock BOLA and XSS vulnerability responses.

### 15.26 Failure Modes
- Target environment state changed (e.g. account deleted) -> Replay fails, candidate tagged `UNVERIFIABLE_STATE_CHANGE` for human review.

### 15.27 Acceptance Criteria
- 100% of false-positive candidate findings rejected in benchmark test suite; valid findings pass with confidence $\ge 0.90$.

### 15.28 Future Extension Points
- Automated PoC exploit script generation engine (Python `requests` / `curl` command builder).

---

## 16. REPORTING ENGINE SPECIFICATION

### 16.1 Purpose
Compiles verified findings and evidence bundles into structured Markdown reports, JSON metrics, and visual timelines for human security researchers.

### 16.2 Responsibilities
- Subscribes to `FindingVerified` events and aggregates associated `Evidence` bundles.
- Formats reports using standard bug bounty templates (HackerOne / Bugcrowd markdown formats).
- Generates reproduction steps, HAR logs, raw HTTP traces, and timeline summaries.

### 16.3 Functional Requirements
- MUST produce valid Markdown document containing Vulnerability Title, Severity (CVSS v3.1), Description, Impact, Steps to Reproduce, and Raw HTTP Evidence.
- MUST export JSON report payload adhering to PenFlow Report Schema.
- MUST NOT include unverified candidates or rejected findings in official reports.

### 16.4 Non-Functional Requirements
- Report generation time < 500 milliseconds per finding.

### 16.5 Inputs
- `VerifiedFinding` objects, `Evidence` bundles, target program metadata.

### 16.6 Outputs
- Markdown report files, `Report` domain objects, `ReportReady` ACP events.

### 16.7 Interfaces
- `IReportingEngine`, `IMarkdownReportFormatter`, `IJSONReportExporter`.

### 16.8 Events Consumed
- `FindingVerified`, `EvidenceBundleCompiled`.

### 16.9 Events Produced
- `ReportReady`, `ReportExported`.

### 16.10 State Management
- In-memory report builder buffer.

### 16.11 Dependencies
- `jinja2` or string template engine, `penflow.domain.models`.

### 16.12 Configuration
- `REPORT_OUTPUT_DIR`, `REPORT_TEMPLATE_FORMAT` (default: "hackerone_markdown").

### 16.13 Security Requirements
- Sanitizes report output to prevent Markdown/HTML injection attacks in reporting dashboards.

### 16.14 Reliability Requirements
- Writes reports atomically to disk using temp file rename patterns to prevent partial file writes.

### 16.15 Scalability Requirements
- Support generating single consolidated reports containing 100+ verified findings.

### 16.16 Performance Requirements
- In-memory template rendering.

### 16.17 Resource Constraints
- RAM overhead < 100 MB.

### 16.18 Error Handling
- Missing evidence fields trigger fallback to `RAW_TRACE_UNAVAILABLE` placeholders without breaking report render.

### 16.19 Retry Policy
- File write lock retried 3 times.

### 16.20 Timeout Policy
- Report generation timeout 5.0 seconds.

### 16.21 Observability Requirements
- Exposes total generated reports, average report generation time gauges.

### 16.22 Logging Requirements
- Log report generation initiation, completed file paths, and export formats.

### 16.23 Metrics
- `penflow_reports_generated_total`, `penflow_report_generation_seconds`.

### 16.24 Audit Requirements
- Generated report hash and file path logged to audit trail.

### 16.25 Testing Requirements
- Unit tests for Jinja2 template rendering; contract tests for JSON report schema validation.

### 16.26 Failure Modes
- Disk output directory read-only -> Report rendering logs error, stores report payload in Quad-Memory database fallback.

### 16.27 Acceptance Criteria
- Rendered Markdown report matches HackerOne submission formatting guidelines 100% in test validation.

### 16.28 Future Extension Points
- Automated PDF export rendering via Headless Chrome / WeasyPrint.

---

## 17. RESOURCE MANAGER SPECIFICATION

### 17.1 Purpose
Monitors and controls system resource consumption including CPU, RAM, network bandwidth, LLM API expenditure, and rate limits.

### 17.2 Responsibilities
- Tracks system CPU/RAM usage and applies execution backpressure when thresholds are breached.
- Tracks LLM API monetary expenditure per campaign and enforces dollar budgets.
- Manages global network rate limiters per target domain.

### 17.3 Functional Requirements
- MUST pause low-priority tasks if system RAM exceeds 85% or CPU exceeds 90%.
- MUST reject LLM API requests if total campaign LLM cost exceeds `MAX_LLM_BUDGET_USD`.
- MUST enforce target HTTP request rates according to target domain rate-limit settings.

### 17.4 Non-Functional Requirements
- Resource sample collection overhead < 0.1% CPU usage.

### 17.5 Inputs
- System metrics (psutil/OS gauges), LLM token usage events, HTTP client request metrics.

### 17.6 Outputs
- `ResourceBudgetAlert` events, rate-limiter token bucket allocations, task pause commands.

### 17.7 Interfaces
- `IResourceManager`, `ILLMBudgetController`, `IRateLimiterRegistry`.

### 17.8 Events Consumed
- `LLMTokenConsumed`, `HTTPRequestInitiated`, `TaskRunning`.

### 17.9 Events Produced
- `ResourceBudgetAlert`, `LLMBudgetExceededFault`, `RateLimitThrottled`.

### 17.10 State Management
- In-memory token bucket rate limiters and cumulative LLM cost counters.

### 17.11 Dependencies
- `psutil` or OS `/proc` reader, `time`, `penflow.core.acp_protocol`.

### 17.12 Configuration
- `MAX_RAM_PERCENT` (default: 85), `MAX_LLM_BUDGET_USD` (default: 50.0), `DEFAULT_RATE_LIMIT_RPS` (default: 10).

### 17.13 Security Requirements
- Cost management parameters cannot be overridden by worker agents or untrusted plugins.

### 17.14 Reliability Requirements
- Thread-safe atomic rate limiter token buckets.

### 17.15 Scalability Requirements
- Track rate limits across 10,000 distinct target subdomains simultaneously.

### 17.16 Performance Requirements
- Lock-free token bucket algorithm $O(1)$.

### 17.17 Resource Constraints
- Resource Manager RAM < 30 MB.

### 17.18 Error Handling
- LLM budget breach raises `LLMBudgetExceededFault`, switching platform automatically to local LLM/heuristic fallbacks.

### 17.19 Retry Policy
- Rate-limited HTTP requests delayed until token bucket refills.

### 17.20 Timeout Policy
- Resource sample check interval 1.0 second.

### 17.21 Observability Requirements
- Exposes system RAM/CPU utilization gauges, cumulative LLM cost counter, active rate limit throttles.

### 17.22 Logging Requirements
- Log resource threshold alerts, LLM budget depletion warnings, and rate limit throttling events.

### 17.23 Metrics
- `penflow_resource_ram_percent`, `penflow_resource_llm_cost_usd_total`, `penflow_resource_rate_limit_throttles_total`.

### 17.24 Audit Requirements
- All resource limit warnings and LLM cost threshold breaches logged to audit trail.

### 17.25 Testing Requirements
- Unit tests for token bucket rate limiting and LLM cost calculation; integration tests for CPU/RAM backpressure triggers.

### 17.26 Failure Modes
- OS `psutil` read failure -> Engine logs warning, defaults to conservative thread-concurrency limits.

### 17.27 Acceptance Criteria
- Token bucket rate limiter restricts HTTP client execution precisely to configured 10 requests/sec in benchmark test.

### 17.28 Future Extension Points
- Cloud auto-scaling triggers based on Resource Manager capacity metrics.

---

## 18. INTELLIGENCE PLATFORM SPECIFICATION

### 18.1 Purpose
Serves as the high-level research processing platform, mining published writeups, building technique dependency graphs, calculating target similarity scores, and recommending optimal attack paths.

### 18.2 Responsibilities
- Mines HackerOne/Bugcrowd writeups and CVE advisories to extract new attack techniques.
- Constructs Technique Graphs linking preconditions, actions, and outputs.
- Computes Target Similarity metrics between target tech stacks.
- Provides recommendations to the Planning Engine.

### 18.3 Functional Requirements
- MUST extract structured `Technique` rules from unstructured markdown writeups.
- MUST calculate Jaccard similarity index between target technology vectors.
- MUST output ranked attack path recommendations.

### 18.4 Non-Functional Requirements
- Target similarity score calculation latency < 10 milliseconds.

### 18.5 Inputs
- Raw writeup text files, Target technology lists.

### 18.6 Outputs
- Extracted `Technique` objects, `TargetSimilarity` scores, `AttackRecommendation` lists.

### 18.7 Interfaces
- `IIntelligencePlatform`, `IWriteupMiner`, `ITechniqueGraphBuilder`, `ITargetSimilarityEngine`.

### 18.8 Events Consumed
- `NewWriteupIngested`, `TargetTechStackIdentified`.

### 18.9 Events Produced
- `TechniqueExtracted`, `SimilarityScoreComputed`, `AttackPathRecommended`.

### 18.10 State Management
- NetworkX / Graph database storing technique dependencies and target similarity clusters.

### 18.11 Dependencies
- `networkx`, `scikit-learn` or `numpy`, `penflow.domain.models`.

### 18.12 Configuration
- `SIMILARITY_THRESHOLD` (default: 0.65), `MAX_RECOMMENDATIONS` (default: 5).

### 18.13 Security Requirements
- Mined writeup content sanitized to prevent prompt injection or script payload execution during analysis.

### 18.14 Reliability Requirements
- Graph persistence to disk on every node modification.

### 18.15 Scalability Requirements
- Graph storage handling 50,000 technique nodes and 200,000 relation edges.

### 18.16 Performance Requirements
- Vectorized matrix operations for similarity calculations.

### 18.17 Resource Constraints
- RAM overhead < 400 MB.

### 18.18 Error Handling
- Mining failure on corrupt writeup logs warning, skips file cleanly.

### 18.19 Retry Policy
- LLM parsing calls retried twice.

### 18.20 Timeout Policy
- Recommendation generation timeout 3.0 seconds.

### 18.21 Observability Requirements
- Exposes technique graph node count, writeups processed counter, recommendation latency.

### 18.22 Logging Requirements
- Log writeup mining progress, technique graph updates, and recommendation scoring details.

### 18.23 Metrics
- `penflow_intelligence_graph_nodes_total`, `penflow_intelligence_writeups_mined_total`.

### 18.24 Audit Requirements
- Technique graph updates and source writeup IDs logged to audit log.

### 18.25 Testing Requirements
- Unit tests for Jaccard similarity scoring; integration tests for graph path traversal.

### 18.26 Failure Modes
- Low writeup dataset -> Engine defaults to standard OWASP Top 10 technique recommendations.

### 18.27 Acceptance Criteria
- Correctly recommends GraphQL BOLA attack path for target matching GraphQL+JWT tech stack signature.

### 18.28 Future Extension Points
- Graph Neural Network (GNN) model integration for automated attack path prediction.

---

## 19. SPECIALIZED SECURITY TEAMS SPECIFICATIONS

This section defines the complete specifications for all 8 specialized Security Testing Teams.

```
┌────────────────────────────────────────────────────────────────────────┐
│                      Specialized Security Teams                        │
├──────────────┬──────────────┬──────────────┬──────────────┬────────────┤
│  IDOR Team   │ GraphQL Team │   JWT Team   │  OAuth Team  │ Logic Team │
├──────────────┼──────────────┼──────────────┼──────────────┼────────────┤
│ API Auth Team│  Cloud Team  │   Web Team   │ Mobile Team  │ Binary Team│
└──────────────┴──────────────┴──────────────┴──────────────┴────────────┘
```

---

### 19.1 IDOR / BOLA SPECIALIZED TEAM SPECIFICATION

#### 19.1.1 Purpose
Executes specialized Insecure Direct Object Reference (IDOR) and Broken Object Level Authorization (BOLA) vulnerability analysis across REST and API endpoints.

#### 19.1.2 Sub-Agents
- `EndpointMapperAgent`: Identifies parameterized endpoints (`/api/users/{id}`).
- `IdentitySwapperAgent`: Swaps authentication tokens (User A vs User B vs Anonymous).
- `ObjectEnumeratorAgent`: Generates numeric, UUID, and hash object ID variations.
- `ResponseDifferAgent`: Computes body/status diffs between authorized and unauthorized requests.
- `PermissionAnalyzerAgent`: Evaluates if response status indicates unauthorized data leakage.
- `ConfidenceCalculatorAgent`: Calculates initial candidate confidence score.

#### 19.1.3 Execution Graph
```
EndpointMapper -> IdentitySwapper -> ObjectEnumerator -> ResponseDiffer -> PermissionAnalyzer -> ConfidenceCalculator
```

#### 19.1.4 Functional Requirements
- MUST require minimum two distinct active sessions (`Identity_A`, `Identity_B`).
- MUST attempt accessing `Identity_A` resources using `Identity_B` session credentials.
- MUST flag IDOR candidate if `Identity_B` receives HTTP 200/201 with matching `Identity_A` data payload.

#### 19.1.5 Non-Functional Requirements
- IDOR test execution cycle < 2.0 seconds per endpoint.

#### 19.1.6 Inputs
- `Endpoint`, `Parameter`, `Identity`, `Session` domain objects (Scoped Context).

#### 19.1.7 Outputs
- `Candidate` finding objects sent to Validation Engine.

#### 19.1.8 Interfaces
- `IIDORTeam`, `IIdentitySwapper`, `IResponseDiffer`.

#### 19.1.9 Events Consumed
- `TaskDispatched(task_type="IDOR_TEST")`.

#### 19.1.10 Events Produced
- `CandidateFindingSubmitted(vuln_type="BOLA_IDOR")`.

#### 19.1.11 State Management
- Task working memory holding response diff trees.

#### 19.1.12 Dependencies
- `httpx`, `penflow.domain.models`, `penflow.core.acp_protocol`.

#### 19.1.13 Configuration
- `IDOR_MAX_ENUMERATION_COUNT` (default: 20), `IDOR_DIFF_THRESHOLD` (default: 0.85).

#### 19.1.14 Security Requirements
- MUST NOT execute mutating DELETE/PUT requests on production object IDs unless explicitly permitted by target scope rules.

#### 19.1.15 Reliability Requirements
- Handles session invalidation by re-authenticating identities automatically.

#### 19.1.16 Scalability Requirements
- Test 1,000 endpoints per campaign concurrently.

#### 19.1.17 Performance Requirements
- Asynchronous parallel HTTP request dispatching.

#### 19.1.18 Resource Constraints
- RAM < 150 MB.

#### 19.1.19 Error Handling
- 401/403 responses evaluated as proper authorization enforcement (No IDOR).

#### 19.1.20 Retry Policy
- Network drops retried twice.

#### 19.1.21 Timeout Policy
- Hard timeout 10.0 seconds per test cycle.

#### 19.1.22 Observability Requirements
- Exposes IDOR tests executed, candidates discovered metrics.

#### 19.1.23 Logging Requirements
- Log identity swap requests, HTTP response status codes, and diff ratios.

#### 19.1.24 Metrics
- `penflow_idor_tests_executed_total`, `penflow_idor_candidates_found_total`.

#### 19.1.25 Audit Requirements
- Raw HTTP traces of cross-session access attempts logged to audit trail.

#### 19.1.26 Testing Requirements
- Unit tests for response diff logic; integration tests against mock BOLA API.

#### 19.1.27 Failure Modes
- Single identity available -> Team logs warning, requests second identity setup from Planner, skips execution.

#### 19.1.28 Acceptance Criteria
- 100% detection of cross-user data leakage on test BOLA endpoint; 0% false positives on properly authorized endpoints.

---

### 19.2 GRAPHQL SPECIALIZED TEAM SPECIFICATION

#### 19.2.1 Purpose
Executes GraphQL security analysis including schema introspection, mutation authorization, alias overloading, batch query analysis, and field-level permissions.

#### 19.2.2 Sub-Agents
- `IntrospectionAnalyzerAgent`: Tests GraphQL Introspection query enabled status.
- `SchemaDiscoveryAgent`: Parses GraphQL AST schemas and extracts mutations/queries.
- `MutationAnalyzerAgent`: Analyzes sensitive state-changing mutations.
- `AliasAnalyzerAgent`: Tests batch query alias amplification limits.
- `AuthorizationAnalyzerAgent`: Tests field-level authorization bypasses.

#### 19.2.3 Execution Graph
```
IntrospectionAnalyzer -> SchemaDiscovery -> MutationAnalyzer -> AliasAnalyzer -> AuthorizationAnalyzer
```

#### 19.2.4 Functional Requirements
- MUST send Introspection query payload to detect exposed schema schemas.
- MUST parse GraphQL AST schema to identify sensitive object types (`User`, `Admin`, `Payment`).
- MUST test alias query batching amplification limits (e.g. 100 aliased queries in single payload).

#### 19.2.5 Non-Functional Requirements
- Introspection analysis < 1.0 second.

#### 19.2.6 Inputs
- `Endpoint` (GraphQL URL), `Session` objects.

#### 19.2.7 Outputs
- `Candidate` finding objects (`GRAPHQL_INTROSPECTION_ENABLED`, `GRAPHQL_ALIAS_BATCHING`, `GRAPHQL_MUTATION_BOLA`).

#### 19.2.8 Interfaces
- `IGraphQLTeam`, `IIntrospectionParser`, `IGraphQLASTAnalyzer`.

#### 19.2.9 Events Consumed
- `TaskDispatched(task_type="GRAPHQL_TEST")`.

#### 19.2.10 Events Produced
- `CandidateFindingSubmitted(vuln_type="GRAPHQL_*")`.

#### 19.2.11 State Management
- In-memory GraphQL AST schema model.

#### 19.2.12 Dependencies
- `graphql-core` or AST parser, `httpx`, `penflow.domain.models`.

#### 19.2.13 Configuration
- `GRAPHQL_MAX_ALIAS_BATCH` (default: 50).

#### 19.2.14 Security Requirements
- Does not execute destructive mutations without mock/test parameters.

#### 19.2.15 Reliability Requirements
- Handles custom GraphQL error envelopes (`{"errors": [...]}`) correctly.

#### 19.2.16 Scalability Requirements
- Parse schemas containing 1,000+ types and mutations.

#### 19.2.17 Performance Requirements
- Fast AST schema parsing.

#### 19.2.18 Resource Constraints
- RAM < 100 MB.

#### 19.2.19 Error Handling
- Disabled introspection triggers fallback to field brute-force schema discovery.

#### 19.2.20 Retry Policy
- Retries transient HTTP errors twice.

#### 19.2.21 Timeout Policy
- Hard timeout 15.0 seconds per test.

#### 19.2.22 Observability Requirements
- Exposes GraphQL endpoints tested, introspection enabled metrics.

#### 19.2.23 Logging Requirements
- Log introspection status, discovered mutations, and alias test results.

#### 19.2.24 Metrics
- `penflow_graphql_tests_total`, `penflow_graphql_candidates_total`.

#### 19.2.25 Audit Requirements
- GraphQL query/mutation payloads and responses logged to audit trail.

#### 19.2.26 Testing Requirements
- Unit tests for GraphQL AST parsing; integration tests against mock GraphQL server.

#### 19.2.27 Failure Modes
- Non-GraphQL endpoint -> Introspection check fails quickly, task terminates safely.

#### 19.2.28 Acceptance Criteria
- Successfully extracts schema when introspection enabled; detects alias batch amplification vulnerability.

---

### 19.3 JWT SPECIALIZED TEAM SPECIFICATION

#### 19.3.1 Purpose
Executes JSON Web Token (JWT) vulnerability tests including algorithm confusion (`alg: none`, `RS256` -> `HS256`), claim tampering, signature stripping, and token replay.

#### 19.3.2 Sub-Agents
- `HeaderAnalyzerAgent`: Parses JWT header algorithm parameters.
- `ClaimAnalyzerAgent`: Tampering user IDs, roles, and expiration claims.
- `AlgorithmAnalyzerAgent`: Tests `alg: none` and public key HMAC confusion.
- `TokenSwapAgent`: Replaces victim token with manipulated token payloads.

#### 19.3.3 Execution Graph
```
HeaderAnalyzer -> ClaimAnalyzer -> AlgorithmAnalyzer -> TokenSwapAgent
```

#### 19.3.4 Functional Requirements
- MUST decode base64url header, payload, and signature components.
- MUST generate modified tokens testing `alg: "none"`, `alg: "NONE"`, `alg: "HS256"` using public key.
- MUST test role claim escalation (`"role": "admin"`).

#### 19.3.5 Non-Functional Requirements
- JWT tampering and signature generation < 1.0 millisecond.

#### 19.3.6 Inputs
- Raw JWT string, `Endpoint`, `Session` domain objects.

#### 19.3.7 Outputs
- `Candidate` findings (`JWT_ALG_NONE`, `JWT_SIG_NOT_VERIFIED`, `JWT_CLAIM_ESCALATION`).

#### 19.3.8 Interfaces
- `IJWTTeam`, `IJWTParser`, `IJWTManipulator`.

#### 19.3.9 Events Consumed
- `TaskDispatched(task_type="JWT_TEST")`.

#### 19.3.10 Events Produced
- `CandidateFindingSubmitted(vuln_type="JWT_*")`.

#### 19.3.11 State Management
- Decoded JWT claim dicts in working memory.

#### 19.3.12 Dependencies
- `pyjwt` or `cryptography`, `base64`, `penflow.domain.models`.

#### 19.3.13 Configuration
- `JWT_PUBLIC_KEY_PATH` (optional).

#### 19.3.14 Security Requirements
- Generated test tokens MUST only be transmitted to target endpoints specified in current task scope.

#### 19.3.15 Reliability Requirements
- Correctly parses non-standard JWT claims without throwing base64 decode exceptions.

#### 19.3.16 Scalability Requirements
- Test 10,000 JWT session tokens per campaign.

#### 19.3.17 Performance Requirements
- In-memory cryptographic signature generation.

#### 19.3.18 Resource Constraints
- RAM < 50 MB.

#### 19.3.19 Error Handling
- Invalid JWT string format causes instant task exit with invalid token status.

#### 19.3.20 Retry Policy
- Retries HTTP swap requests twice on connection error.

#### 19.3.21 Timeout Policy
- Hard timeout 5.0 seconds per JWT test cycle.

#### 19.3.22 Observability Requirements
- Exposes JWT tokens analyzed, tampered tokens accepted metrics.

#### 19.3.23 Logging Requirements
- Log decoded claims, modified header parameters, and server HTTP response status.

#### 19.3.24 Metrics
- `penflow_jwt_tests_total`, `penflow_jwt_vulnerabilities_found_total`.

#### 19.3.25 Audit Requirements
- Tampered JWT payload and server acceptance response logged to audit trail.

#### 19.3.26 Testing Requirements
- Unit tests for `alg: none` token generation; integration tests against mock JWT auth server.

#### 19.3.27 Failure Modes
- Server rejects tampered token with 401/403 -> Test completes with zero vulnerability finding.

#### 19.3.28 Acceptance Criteria
- Successfully detects server accepting `alg: none` or unsigned JWT claims in test environment.

---

### 19.4 OAUTH SPECIALIZED TEAM SPECIFICATION

#### 19.4.1 Purpose
Analyzes OAuth 2.0 and OpenID Connect (OIDC) authentication flows for redirect URI manipulation, PKCE downgrades, CSRF state parameters, and token leakages.

#### 19.4.2 Sub-Agents
- `FlowDetectorAgent`: Identifies OAuth endpoints (`/oauth/authorize`, `/oauth/token`).
- `RedirectAnalyzerAgent`: Tests open redirect and domain wildcard matching in `redirect_uri`.
- `PKCEAnalyzerAgent`: Tests missing PKCE (`code_verifier` / `code_challenge`) enforcement.
- `ScopeAnalyzerAgent`: Tests scope escalation (`scope=openid+profile+admin`).

#### 19.4.3 Execution Graph
```
FlowDetector -> RedirectAnalyzer -> PKCEAnalyzer -> ScopeAnalyzer
```

#### 19.4.4 Functional Requirements
- MUST inspect OAuth authorization URLs for `redirect_uri`, `state`, `response_type`, and `scope`.
- MUST test modifying `redirect_uri` to attacker-controlled external subdomains.
- MUST test authorization code grant without `code_challenge` parameter.

#### 19.4.5 Non-Functional Requirements
- OAuth flow analysis < 2.0 seconds per flow.

#### 19.4.6 Inputs
- OAuth Authorization URLs, `Endpoint` objects.

#### 19.4.7 Outputs
- `Candidate` findings (`OAUTH_OPEN_REDIRECT`, `OAUTH_MISSING_STATE`, `OAUTH_PKCE_BYPASS`).

#### 19.4.8 Interfaces
- `IOAuthTeam`, `IOAuthURLParser`, `IRedirectURIValidator`.

#### 19.4.9 Events Consumed
- `TaskDispatched(task_type="OAUTH_TEST")`.

#### 19.4.10 Events Produced
- `CandidateFindingSubmitted(vuln_type="OAUTH_*")`.

#### 19.4.11 State Management
- OAuth authorization parameters dict in working memory.

#### 19.4.12 Dependencies
- `urllib.parse`, `httpx`, `penflow.domain.models`.

#### 19.4.13 Configuration
- `ATTACKER_REDIRECT_CANARY_DOMAIN` (default: "canary.penflow.local").

#### 19.4.14 Security Requirements
- Redirect URI testing CANNOT send credentials to untrusted third-party public domains.

#### 19.4.15 Reliability Requirements
- Handles OAuth provider 302 redirects without following untrusted destination redirects automatically.

#### 19.4.16 Scalability Requirements
- Test 500 OAuth integration flows per campaign.

#### 19.4.17 Performance Requirements
- In-memory URL parameter string manipulation.

#### 19.4.18 Resource Constraints
- RAM < 50 MB.

#### 19.4.19 Error Handling
- Invalid OAuth URL format logs parsing error, exits task safely.

#### 19.4.20 Retry Policy
- Retries HTTP authorization requests twice.

#### 19.4.21 Timeout Policy
- Hard timeout 10.0 seconds per OAuth test.

#### 19.4.22 Observability Requirements
- Exposes OAuth flows tested, candidate vulnerabilities discovered metrics.

#### 19.4.23 Logging Requirements
- Log OAuth parameters, modified `redirect_uri` payloads, and 302 Location headers.

#### 19.4.24 Metrics
- `penflow_oauth_tests_total`, `penflow_oauth_candidates_total`.

#### 19.4.25 Audit Requirements
- OAuth authorization request/response headers logged to audit trail.

#### 19.4.26 Testing Requirements
- Unit tests for OAuth URL parameter extraction; integration tests against mock OAuth server.

#### 19.4.27 Failure Modes
- Strict redirect URI validation enforced by server -> Test completes cleanly with zero finding.

#### 19.4.28 Acceptance Criteria
- Correctly flags missing `state` parameter and open `redirect_uri` vulnerability on test OAuth endpoint.

---

### 19.5 BUSINESS LOGIC SPECIALIZED TEAM SPECIFICATION

#### 19.5.1 Purpose
Analyzes multi-step workflow logic, state machine transitions, race conditions, price manipulations, and cart/coupon bypasses.

#### 19.5.2 Sub-Agents
- `WorkflowBuilderAgent`: Maps multi-step transactional state transitions (Draft -> Cart -> Payment -> Fulfilled).
- `RaceConditionAgent`: Tests parallel concurrent HTTP requests (Limit Overrun / Double Spend).
- `PriceManipulationAgent`: Tests negative numeric values and floating-point rounding in price parameters.
- `CouponAgent`: Tests concurrent coupon code redemption and replay.

#### 19.5.3 Execution Graph
```
WorkflowBuilder -> RaceConditionAgent & PriceManipulationAgent & CouponAgent
```

#### 19.5.4 Functional Requirements
- MUST send parallel concurrent HTTP requests (10-50 synchronized requests via HTTP/2 or single-packet send) to test Race Conditions.
- MUST test negative values (`quantity: -1`, `price: -100.00`) in transactional endpoints.
- MUST test out-of-order state transitions (skipping Payment step directly to Fulfillment step).

#### 19.5.5 Non-Functional Requirements
- Parallel race condition burst synchronization jitter < 2.0 milliseconds across requests.

#### 19.5.6 Inputs
- `Workflow`, `Endpoint`, `Parameter`, `Session` domain objects.

#### 19.5.7 Outputs
- `Candidate` findings (`RACE_CONDITION_DOUBLE_SPEND`, `BUSINESS_LOGIC_PRICE_MANIPULATION`, `STATE_MACHINE_BYPASS`).

#### 19.5.8 Interfaces
- `IBusinessLogicTeam`, `IWorkflowMapper`, `IRaceConditionRunner`.

#### 19.5.9 Events Consumed
- `TaskDispatched(task_type="BUSINESS_LOGIC_TEST")`.

#### 19.5.10 Events Produced
- `CandidateFindingSubmitted(vuln_type="BUSINESS_LOGIC_*")`.

#### 19.5.11 State Management
- Multi-step workflow state machine graph.

#### 19.5.12 Dependencies
- `asyncio`, `httpx` (HTTP/2 multiplexing), `penflow.domain.models`.

#### 19.5.13 Configuration
- `RACE_BURST_CONCURRENCY` (default: 20), `TEST_NEGATIVE_NUMBERS` (default: true).

#### 19.5.14 Security Requirements
- MUST use test sandbox accounts and test payment gateway tokens; REAL CREDIT CARDS ARE STRICTLY FORBIDDEN.

#### 19.5.15 Reliability Requirements
- Handles target server 500 errors during race condition bursts without crashing execution pool.

#### 19.5.16 Scalability Requirements
- Test 100 transactional workflows per campaign.

#### 19.5.17 Performance Requirements
- High-precision barrier synchronization for race condition request bursts.

#### 19.5.18 Resource Constraints
- RAM < 200 MB.

#### 19.5.19 Error Handling
- Transaction failure logs state error, rolls back test workflow state safely.

#### 19.5.20 Retry Policy
- Race condition tests retried up to 3 times to account for timing jitter.

#### 19.5.21 Timeout Policy
- Hard timeout 20.0 seconds per workflow execution.

#### 19.5.22 Observability Requirements
- Exposes workflows tested, race condition bursts executed, business logic candidates found metrics.

#### 19.5.23 Logging Requirements
- Log workflow state transitions, parameter overrides, and parallel burst response status codes.

#### 19.24 Metrics
- `penflow_logic_workflows_tested_total`, `penflow_logic_race_conditions_found_total`.

#### 19.5.25 Audit Requirements
- Transactional state logs and parallel request timestamps logged to audit trail.

#### 19.5.26 Testing Requirements
- Unit tests for barrier synchronization timing; integration tests against mock vulnerable cart API.

#### 19.5.27 Failure Modes
- Server locks rows atomically -> Race condition test yields identical responses with zero duplicate processing (No vuln).

#### 19.5.28 Acceptance Criteria
- Successfully detects double-redemption of single-use promo code under parallel race condition burst testing.

---

### 19.6 API AUTHORIZATION SPECIALIZED TEAM SPECIFICATION

#### 19.6.1 Purpose
Executes Broken Function Level Authorization (BFLA), Mass Assignment, HTTP Method Overrides, and Parameter Pollution (HPP) security tests across API endpoints.

#### 19.6.2 Sub-Agents
- `BFLAAgent`: Tests low-privilege user access to administrative API endpoints (`/api/admin/users`).
- `MassAssignmentAgent`: Injects hidden model properties (`"is_admin": true`, `"role": "superuser"`) into JSON request bodies.
- `HTTPMethodAgent`: Tests HTTP verb tampering (`GET` -> `POST` / `PUT` / `DELETE` / `PATCH`).
- `ParameterPollutionAgent`: Injects duplicate query parameters (`?user_id=101&user_id=102`).

#### 19.6.3 Execution Graph
```
BFLAAgent & MassAssignmentAgent & HTTPMethodAgent & ParameterPollutionAgent
```

#### 19.6.4 Functional Requirements
- MUST attempt executing administrative endpoints using standard non-admin session tokens (BFLA test).
- MUST inject unexpected JSON schema properties into PUT/POST request bodies (Mass Assignment test).
- MUST test overriding HTTP methods via headers (`X-HTTP-Method-Override: PUT`) and alternative verbs.

#### 19.6.5 Non-Functional Requirements
- API authorization test cycle < 1.5 seconds per endpoint.

#### 19.6.6 Inputs
- `Endpoint`, `Parameter`, `Identity`, `Session` domain objects.

#### 19.6.7 Outputs
- `Candidate` findings (`BFLA_ADMIN_ACCESS`, `MASS_ASSIGNMENT_ROLE_ESCALATION`, `HTTP_METHOD_OVERRIDE_BYPASS`).

#### 19.6.8 Interfaces
- `IAPIAuthorizationTeam`, `IBFLAAnalyzer`, `IMassAssignmentInjector`.

#### 19.6.9 Events Consumed
- `TaskDispatched(task_type="API_AUTH_TEST")`.

#### 19.6.10 Events Produced
- `CandidateFindingSubmitted(vuln_type="API_AUTH_*")`.

#### 19.6.11 State Management
- Injected parameter schemas and response status maps in working memory.

#### 19.6.12 Dependencies
- `httpx`, `json`, `penflow.domain.models`.

#### 19.6.13 Configuration
- `MASS_ASSIGNMENT_PROPERTIES` (default: ["is_admin", "role", "permissions", "tenant_id"]).

#### 19.6.14 Security Requirements
- Mass assignment payloads MUST use non-destructive benign values (`"penflow_test": true`).

#### 19.6.15 Reliability Requirements
- Handles API schema validation errors (400 Bad Request) cleanly without failing test queue.

#### 19.6.16 Scalability Requirements
- Test 5,000 API endpoints per campaign.

#### 19.6.17 Performance Requirements
- Parallel asynchronous request dispatches.

#### 19.6.18 Resource Constraints
- RAM < 150 MB.

#### 19.6.19 Error Handling
- Server 403 Forbidden logs valid authorization enforcement.

#### 19.6.20 Retry Policy
- Network connection drops retried twice.

#### 19.6.21 Timeout Policy
- Hard timeout 10.0 seconds per endpoint.

#### 19.6.22 Observability Requirements
- Exposes API endpoints tested, BFLA and Mass Assignment candidates found metrics.

#### 19.6.23 Logging Requirements
- Log injected JSON properties, modified HTTP verbs, and server response codes.

#### 19.6.24 Metrics
- `penflow_api_auth_tests_total`, `penflow_bfla_candidates_total`, `penflow_mass_assignment_candidates_total`.

#### 19.6.25 Audit Requirements
- Raw HTTP request bodies containing injected properties logged to audit trail.

#### 19.6.26 Testing Requirements
- Unit tests for JSON property injection; integration tests against mock BFLA administrative API.

#### 19.6.27 Failure Modes
- Server uses strict DTO schema validation -> Injected properties stripped/rejected with 400 Bad Request (No vuln).

#### 19.6.28 Acceptance Criteria
- Successfully detects regular user accessing `/api/admin/metrics` endpoint (BFLA) and updating `"is_admin": true` (Mass Assignment).

---

### 19.7 CLOUD SECURITY SPECIALIZED TEAM SPECIFICATION

#### 19.7.1 Purpose
Analyzes cloud storage buckets (AWS S3, GCP Storage, Azure Blobs), IAM misconfigurations, exposed cloud metadata endpoints, and DNS subdomain takeovers.

#### 19.7.2 Sub-Agents
- `BucketAgent`: Tests public read/write/list permissions on S3/GCP buckets (`http://bucket.s3.amazonaws.com`).
- `MetadataAgent`: Tests SSRF access to Instance Metadata Services (`http://169.254.169.254/latest/meta-data/`).
- `SubdomainTakeoverAgent`: Tests dangling CNAME DNS records pointing to unclaimed cloud resources (GitHub Pages, S3, Heroku).

#### 19.7.3 Execution Graph
```
BucketAgent & MetadataAgent & SubdomainTakeoverAgent
```

#### 19.7.4 Functional Requirements
- MUST query bucket URLs for anonymous `GET`, `PUT`, and `LIST` access.
- MUST test cloud metadata IP addresses (`169.254.169.254`, `metadata.google.internal`) during SSRF evaluations.
- MUST query CNAME DNS records for unresolved target hostnames returning 404 cloud provider status signatures.

#### 19.7.5 Non-Functional Requirements
- DNS CNAME resolution < 50 milliseconds per domain.

#### 19.7.6 Inputs
- `Asset` (Subdomain, IP, Bucket URL), `Observation` objects.

#### 19.7.7 Outputs
- `Candidate` findings (`PUBLIC_S3_BUCKET_READ`, `PUBLIC_S3_BUCKET_WRITE`, `CLOUD_METADATA_EXPOSED`, `SUBDOMAIN_TAKEOVER_RISK`).

#### 19.7.8 Interfaces
- `ICloudTeam`, `IBucketPermissionsTester`, `ISubdomainTakeoverChecker`.

#### 19.7.9 Events Consumed
- `TaskDispatched(task_type="CLOUD_TEST")`.

#### 19.7.10 Events Produced
- `CandidateFindingSubmitted(vuln_type="CLOUD_*")`.

#### 19.7.11 State Management
- In-memory CNAME signature patterns database.

#### 19.7.12 Dependencies
- `dnspython`, `httpx`, `penflow.domain.models`.

#### 19.7.13 Configuration
- `TAKEOVER_SIGNATURES_PATH` (default: "cloud_takeover_signatures.json").

#### 19.7.14 Security Requirements
- Bucket write tests MUST write a temporary benign text file (`penflow_proof.txt`) and delete it immediately after verification.

#### 19.7.15 Reliability Requirements
- Handles DNS resolution timeouts gracefully without halting execution queue.

#### 19.7.16 Scalability Requirements
- Check 50,000 subdomains for cloud takeover risks per campaign.

#### 19.7.17 Performance Requirements
- High-concurrency async DNS queries.

#### 19.7.18 Resource Constraints
- RAM < 100 MB.

#### 19.7.19 Error Handling
- Bucket 403 Access Denied logged as secure bucket (No vuln).

#### 19.7.20 Retry Policy
- DNS queries retried twice on timeout.

#### 19.7.21 Timeout Policy
- Hard timeout 5.0 seconds per cloud check.

#### 19.7.22 Observability Requirements
- Exposes cloud buckets tested, public buckets found, takeover risks found metrics.

#### 19.7.23 Logging Requirements
- Log bucket permission responses, CNAME targets, and metadata response status.

#### 19.7.24 Metrics
- `penflow_cloud_buckets_tested_total`, `penflow_cloud_takeovers_found_total`.

#### 19.7.25 Audit Requirements
- Bucket access proof and CNAME DNS lookup records logged to audit trail.

#### 19.7.26 Testing Requirements
- Unit tests for CNAME takeover signature matching; integration tests against mock public S3 bucket.

#### 19.7.27 Failure Modes
- Bucket requires AWS SigV4 signed request -> Anonymous request returns 403 Forbidden cleanly.

#### 19.7.28 Acceptance Criteria
- Successfully detects publicly listable S3 bucket and unclaimed CNAME pointing to dangling GitHub Pages site.

---

### 19.8 WEB SECURITY SPECIALIZED TEAM SPECIFICATION

#### 19.8.1 Purpose
Executes classic web application security analysis including Cross-Site Scripting (XSS), CORS misconfigurations, CSRF defenses, SSRF, SSTI, and HTTP Security Headers.

#### 19.8.2 Sub-Agents
- `CORSAgent`: Tests `Origin` header reflection (`Origin: https://evil.com`) with `Access-Control-Allow-Credentials: true`.
- `XSSAgent`: Tests benign context-aware reflection of alphanumeric canary strings (`penflowxss123`).
- `SSRFAgent`: Tests HTTP request reflection against internal loopback and metadata IPs.
- `SecurityHeadersAgent`: Analyzes `CSP`, `HSTS`, `X-Frame-Options`, and `SameSite` cookie flags.

#### 19.8.3 Execution Graph
```
CORSAgent & XSSAgent & SSRFAgent & SecurityHeadersAgent
```

#### 19.8.4 Functional Requirements
- MUST send custom `Origin` header payloads to test CORS wildcards with credentials.
- MUST inject harmless canary tokens (`penflowcanary`) to test HTML/JS reflection contexts without executing executable JS code.
- MUST inspect HTTP response headers for missing HSTS, CSP, and insecure Cookie flags.

#### 19.8.5 Non-Functional Requirements
- Header and reflection test execution latency < 1.0 second per endpoint.

#### 19.8.6 Inputs
- `Endpoint`, `Parameter`, `Observation` objects.

#### 19.8.7 Outputs
- `Candidate` findings (`CORS_MISCONFIGURATION`, `XSS_REFLECTED_CANARY`, `SSRF_INTERNAL_REACHABLE`, `MISSING_SECURITY_HEADERS`).

#### 19.8.8 Interfaces
- `IWebTeam`, `ICORSAnalyzer`, `IXSSReflectionTester`.

#### 19.8.9 Events Consumed
- `TaskDispatched(task_type="WEB_TEST")`.

#### 19.8.10 Events Produced
- `CandidateFindingSubmitted(vuln_type="WEB_*")`.

#### 19.8.11 State Management
- Reflection context AST/DOM parsing tree in working memory.

#### 19.8.12 Dependencies
- `httpx`, `html.parser`, `penflow.domain.models`.

#### 19.8.13 Configuration
- `CANARY_PREFIX` (default: "penflow_canary_").

#### 19.8.14 Security Requirements
- XSS TESTS MUST NOT INJECT EXECUTABLE EXPLOIT PAYLOADS (`<script>alert(1)</script>`); USE STRICTLY BENIGN CANARY REFLECTION TOKENS.

#### 19.8.15 Reliability Requirements
- Handles WAF blocking by detecting 406/429 status codes and backing off.

#### 19.8.16 Scalability Requirements
- Test 10,000 web parameters per campaign.

#### 19.8.17 Performance Requirements
- Asynchronous HTTP reflection testing.

#### 19.8.18 Resource Constraints
- RAM < 150 MB.

#### 19.8.19 Error Handling
- Connection reset by WAF logged as `WAF_INTERFERENCE` and skipped safely.

#### 19.8.20 Retry Policy
- Retries HTTP reflection requests twice.

#### 19.8.21 Timeout Policy
- Hard timeout 10.0 seconds per endpoint.

#### 19.8.22 Observability Requirements
- Exposes parameters tested for reflection, CORS misconfigurations found metrics.

#### 19.8.23 Logging Requirements
- Log Origin header responses, reflection context locations (HTML body, attribute, JS string), and security header audit results.

#### 19.8.24 Metrics
- `penflow_web_parameters_tested_total`, `penflow_cors_misconfigurations_found_total`.

#### 19.8.25 Audit Requirements
- Raw HTTP request/response traces of CORS reflection and canary injections logged to audit trail.

#### 19.8.26 Testing Requirements
- Unit tests for CORS header parsing; integration tests against mock vulnerable CORS web app.

#### 19.8.27 Failure Modes
- WAF blocks canary parameter -> Reflection test marks parameter `WAF_BLOCKED`, exits task cleanly.

#### 19.8.28 Acceptance Criteria
- Successfully flags `Access-Control-Allow-Origin: https://evil.com` + `Access-Control-Allow-Credentials: true` misconfiguration in test suite.

---

## 20. HUMAN REVIEW LAYER SPECIFICATION

### 20.1 Purpose
Provides the security analyst dashboard interface for reviewing verified findings, inspecting evidence bundles, approving final bug bounty reports, and delivering feedback to the Learning Engine.

### 20.2 Responsibilities
- Displays `VerifiedFinding` entries with associated CVSS scores, Markdown reports, and raw HTTP evidence bundles.
- Captures human decision commands (`APPROVE_REPORT`, `REJECT_REPORT`, `REQUEST_RETEST`).
- Feeds human feedback back to the Learning Engine to refine Experience Layer heuristics.

### 20.3 Functional Requirements
- MUST render complete evidence bundle (HAR logs, screenshots, HTTP request/response diffs).
- MUST require explicit human analyst click/command approval before exporting report to external bug bounty platforms.
- MUST emit `HumanFeedbackSubmitted` event upon analyst approval or rejection.

### 20.4 Non-Functional Requirements
- Dashboard UI page render time < 200 milliseconds.

### 20.5 Inputs
- `VerifiedFinding`, `Evidence`, `Report` domain objects.

### 20.6 Outputs
- `HumanFeedbackSubmitted` events, approved `Report` exports.

### 20.7 Interfaces
- `IHumanReviewLayer`, `IReviewDashboardAPI`, `IFeedbackCollector`.

### 20.8 Events Consumed
- `ReportReady`, `FindingVerified`.

### 20.9 Events Produced
- `ReportApprovedByHuman`, `ReportRejectedByHuman`, `HumanFeedbackSubmitted`.

### 20.10 State Management
- Review queue status map (`finding_id` -> {status: "PENDING_REVIEW" | "APPROVED" | "REJECTED", analyst_notes}).

### 20.11 Dependencies
- `penflow.domain.models`, `penflow.core.acp_protocol`.

### 20.12 Configuration
- `HUMAN_REVIEW_PORT` (default: 8080), `AUTO_APPROVE_ENABLED` (MUST BE false).

### 20.13 Security Requirements
- Dashboard MUST require analyst authentication (Session Auth / API Token).
- UNATTENDED AUTOMATIC REPORT SUBMISSION TO EXTERNAL PLATFORMS IS STRICTLY FORBIDDEN.

### 20.14 Reliability Requirements
- Review state persisted to SQLite Quad-Memory; session state preserved across web server restarts.

### 20.15 Scalability Requirements
- Handle review queue containing 1,000 pending verified findings.

### 20.16 Performance Requirements
- Fast JSON REST API endpoints for UI dashboard.

### 20.17 Resource Constraints
- Dashboard RAM overhead < 100 MB.

### 20.18 Error Handling
- Invalid analyst command returns 400 Bad Request with error description.

### 20.19 Retry Policy
- Database lock retries up to 3 times.

### 20.20 Timeout Policy
- API endpoint request timeout 5.0 seconds.

### 20.21 Observability Requirements
- Exposes pending review queue depth, approved reports total, rejected reports total.

### 20.22 Logging Requirements
- Log analyst login events, report approvals, rejections, and feedback notes.

### 20.23 Metrics
- `penflow_human_review_pending_total`, `penflow_human_reports_approved_total`, `penflow_human_reports_rejected_total`.

### 20.24 Audit Requirements
- 100% of human review decisions, timestamps, and analyst IDs logged to audit trail.

### 20.25 Testing Requirements
- Unit tests for review state transitions; integration tests for emitting `HumanFeedbackSubmitted` events to Learning Engine.

### 20.26 Failure Modes
- Dashboard web server crash -> System remains safe; findings remain queued safely in Quad-Memory database until web server restarts.

### 20.27 Acceptance Criteria
- Human analyst can view HAR log evidence, click "Approve", and verify report export event generation in test integration run.

### 20.28 Future Extension Points
- Browser extension connector for live in-browser finding reproduction.

---

## 21. TEST SPECIFICATION MANDATE (TEST-BEFORE-CODE PROTOCOL)

Prior to writing implementation source code for ANY subsystem specified in Sections 1 through 20, the engineering team MUST construct the complete test suite adhering to the Test-Before-Code Protocol:

```
                  Test-Before-Code Workflow
                  
┌─────────────────────────┐
│ Write Subsystem PES Spec│ (Sections 1-20)
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ Write Unit & Contract   │ (e.g. tests/test_acp_engine.py)
│ Test Suite (Failing ❌) │
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ Implement Subsystem     │ (e.g. penflow/core/acp_engine.py)
│ Source Code             │
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ Execute Pytest Suite    │
│ (All Pass 100% Green ✅) │
└─────────────────────────┘
```

1. **Step 1:** Read Subsystem Specification in PES v1.0.
2. **Step 2:** Write automated unit and contract test files under `tests/` defining expected inputs, outputs, and boundary failures (Tests initially fail ❌).
3. **Step 3:** Write subsystem Python implementation code under `penflow/`.
4. **Step 4:** Execute `python -m pytest` until 100% of tests pass green ✅.

---
*End of PenFlow Engineering Specification (PES v1.0)*  
*Certified Implementation-Ready by Lead Systems Engineer.*
