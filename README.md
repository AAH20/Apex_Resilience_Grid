# Apex Resilience Grid — Critical Infrastructure Resilience Platform

Cross-domain orchestration, cascading failure analysis, self-healing, NIST/CISA compliance, SCADA/ICS integration, digital twin, zero-trust architecture, and post-quantum cryptography for critical infrastructure.

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Resilience Grid Architecture](#resilience-grid-architecture)
- [Cross-Domain Event Bus](#cross-domain-event-bus)
- [Cascading Failure Analysis](#cascading-failure-analysis)
- [Self-Healing Framework](#self-healing-framework)
- [NIST / CISA Compliance](#nist--cisa-compliance)
- [SCADA / ICS Integration](#scada--ics-integration)
- [Digital Twin](#digital-twin)
- [Zero-Trust Architecture](#zero-trust-architecture)
- [Post-Quantum Cryptography](#post-quantum-cryptography)
- [Benchmark Comparisons](#benchmark-comparisons)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Testing](#testing)
- [License](#license)

---

## Architecture Overview

Apex Resilience Grid is a Python-based platform for modeling, analyzing, and orchestrating resilience across four critical infrastructure domains: **Energy**, **Water**, **Transport**, and **Emergency Services**. It provides real-time cascading failure analysis, automated self-healing, compliance reporting, and quantum-resistant secure communications.

```mermaid
graph TB
    subgraph External["External Systems"]
        SCADA[SCADA / ICS]
        OT[OT Network]
        IT[IT Network]
    end

    subgraph Core["Apex Resilience Grid Core"]
        EB[Cross-Domain Event Bus]
        ORC[Cross-Domain Orchestrator]
        CFA[Cascading Failure Analyzer]
        SH[Self-Healing Engine]
        DT[Digital Twin]
        ZT[Zero-Trust Engine]
        PQC[PQC Module]
        COMP[Compliance Engine]
    end

    subgraph Domains["Infrastructure Domains"]
        EN[Energy]
        WA[Water]
        TR[Transport]
        EM[Emergency]
    end

    SCADA -->|Readings / Alarms| EB
    OT -->|OT→IT Gateway| EB
    IT -->|Commands| ZT

    EB --> ORC
    EB --> CFA
    EB --> SH
    ORC --> EN & WA & TR & EM
    CFA --> DT
    SH -->|Failover / Recovery| ORC
    DT -->|Predictions| CFA
    ZT -->|AuthZ / AuthN| EB
    PQC -->|Encrypted Channels| ZT
    COMP -->|Audit Trail| EB
```

---

## Resilience Grid Architecture

The resilience grid models infrastructure as a directed graph of **nodes** (assets) and **dependencies** (edges). Nodes belong to one of four domains. Dependencies can cross domain boundaries, enabling realistic modeling of interdependent critical infrastructure.

```mermaid
graph LR
    subgraph Energy["⚡ Energy Domain"]
        PP1[Power Plant 1<br/>capacity: 100]
        SS1[Substation 1<br/>capacity: 80]
        SS2[Substation 2<br/>capacity: 60]
    end

    subgraph Water["💧 Water Domain"]
        WP1[Water Plant 1<br/>capacity: 50]
        PS1[Pump Station 1<br/>capacity: 30]
    end

    subgraph Transport["🚛 Transport Domain"]
        TH1[Traffic Hub 1<br/>capacity: 40]
        TH2[Traffic Hub 2<br/>capacity: 35]
    end

    subgraph Emergency["🚨 Emergency Domain"]
        HOSP[Hospital 1<br/>capacity: 20]
        FIRE[Fire Station 1<br/>capacity: 15]
    end

    PP1 -->|depends on| SS1
    PP1 -->|depends on| SS2
    SS1 -->|depends on| WP1
    SS1 -->|depends on| PS1
    SS2 -->|depends on| TH1
    SS2 -->|depends on| TH2
    SS1 -->|depends on| HOSP
    WP1 -->|depends on| HOSP
    SS2 -->|depends on| FIRE
    WP1 -->|depends on| FIRE
```

### Core Data Models

| Class | Description |
|-------|-------------|
| `Grid` | Container for nodes and dependencies |
| `Node` | Infrastructure asset with `id`, `domain`, `capacity`, `metadata` |
| `Dependency` | Directed edge: `source` depends on `target` |
| `Domain` | Infrastructure domain enum (energy, water, transport, emergency) |
| `CascadingResult` | Result of cascading failure analysis |

### Cross-Domain Orchestrator

The `CrossDomainOrchestrator` provides domain-level operations:

- **`get_domains()`** — enumerate all domains in the grid
- **`get_nodes_by_domain(domain)`** — list nodes in a domain
- **`get_cross_domain_dependencies()`** — find inter-domain edges
- **`get_domain_health(domain)`** — aggregate health metrics
- **`isolate_domain(domain)`** — blast-radius isolation

---

## Cross-Domain Event Bus

The event bus is the central nervous system of the grid. It provides publish/subscribe routing with domain filtering, priority-ordered handlers, wildcard subscriptions, dead-letter capture, and per-delivery error isolation.

```mermaid
sequenceDiagram
    participant Src as Source Domain
    participant Bus as Event Bus
    participant R as Entity Resolver
    participant Sub as Subscriber (Domain-Filtered)
    participant DL as Dead Letter Queue

    Src->>Bus: publish(Event)
    Bus->>R: resolve(entity_refs)
    R-->>Bus: DomainEntity[]

    alt No matching subscribers
        Bus->>DL: dead_letter(event)
    else Matching subscribers
        Bus->>Sub: handler(event) [priority order]
        alt Handler succeeds
            Sub-->>Bus: Delivery(delivered=true)
        else Handler fails
            Sub-->>Bus: Delivery(delivered=false, error=...)
        end
    end

    Bus-->>Src: DeliveryReport
```

### Event Bus Components

```mermaid
classDiagram
    class EventBus {
        -_subscribers: Dict[str, List]
        -_by_id: Dict[str, Tuple]
        -dead_letters: List[Event]
        +subscribe(event_type, handler, priority, domains) -> str
        +unsubscribe(subscriber_id) -> bool
        +publish(event) -> DeliveryReport
        +get_subscribers(event_type, domain) -> List[str]
    }

    class EntityResolver {
        -_entities: Dict[str, DomainEntity]
        -_by_domain: Dict[Domain, Dict]
        -_aliases: Dict[str, str]
        +register(entity) -> None
        +add_alias(entity_ref, alias) -> None
        +resolve(ref) -> DomainEntity
        +resolve_all(refs) -> List[DomainEntity]
    }

    class DependencyTracker {
        -_graph: Dict[str, Set]
        -_reverse: Dict[str, Set]
        +add_dependency(dependent, dependency, relation) -> DependencyEdge
        +remove_dependency(dependent, dependency) -> bool
        +dependencies_of(entity_ref) -> List[str]
        +dependents_of(entity_ref) -> List[str]
        +dependency_path(start, goal) -> Optional[List[str]]
        +cascade(origins, max_hops) -> CascadeResult
        +has_cycle() -> bool
    }

    class Event {
        +event_type: str
        +source_domain: Domain
        +entity_refs: List[str]
        +target_domains: Optional[List[Domain]]
        +payload: Dict
        +event_id: str
    }

    class DeliveryReport {
        +event: Event
        +deliveries: List[Delivery]
        +resolved_entities: List[DomainEntity]
        +unresolved_refs: List[str]
        +dead_lettered: bool
        +delivered_count: int
        +failed_count: int
    }

    EventBus --> EntityResolver : uses
    EventBus --> Event : publishes
    EventBus --> DeliveryReport : returns
    DependencyTracker --> EntityResolver : uses
```

### Entity Resolution

The `EntityResolver` supports three reference formats:

| Format | Example | Description |
|--------|---------|-------------|
| Qualified ID | `energy:feeder-1` | Explicit domain + entity ID |
| Alias | `grid-feeder` | Human-friendly alias bound to an entity |
| Bare ID | `feeder-1` | Unique across all domains (ambiguous → error) |

### Dependency Tracker Cascade

The `DependencyTracker` performs BFS-based cascade analysis across the inter-domain dependency graph:

```mermaid
graph LR
    FE["energy:feeder-1"] -->|hop 1| WP["water:pump-1"]
    WP -->|hop 2| TH["transport:hub-1"]
    TH -->|hop 3| SH["emergency:shelter-1"]

    style FE fill:#ff6b6b,color:#fff
    style WP fill:#ffa94d,color:#fff
    style TH fill:#ffd43b,color:#000
    style SH fill:#69db7c,color:#000
```

---

## Cascading Failure Analysis

The `CascadingFailureAnalyzer` models failure propagation through the dependency graph using **conjunctive propagation**: a node fails only when ALL its strong dependencies (weight ≥ threshold) have failed. This correctly models redundancy — a node with multiple power sources survives the loss of one.

```mermaid
flowchart TD
    A[Power Plant 1] -->|weight: 1.0| B[Substation 1]
    A -->|weight: 1.0| C[Substation 2]
    B -->|weight: 1.0| D[Water Plant 1]
    B -->|weight: 1.0| E[Pump Station 1]
    C -->|weight: 1.0| F[Traffic Hub 1]
    C -->|weight: 1.0| G[Traffic Hub 2]
    B -->|weight: 1.0| H[Hospital 1]
    D -->|weight: 1.0| H
    C -->|weight: 1.0| I[Fire Station 1]
    D -->|weight: 1.0| I

    style A fill:#ff6b6b,color:#fff
    style B fill:#ffa94d,color:#fff
    style C fill:#ffa94d,color:#fff
    style D fill:#ffd43b,color:#000
    style E fill:#ffd43b,color:#000
    style F fill:#ffd43b,color:#000
    style G fill:#ffd43b,color:#000
    style H fill:#69db7c,color:#000
    style I fill:#69db7c,color:#000
```

### Failure Propagation Algorithm

```mermaid
flowchart LR
    START([Start: node fails]) --> INIT[Initialize failed set<br/>with origin node]
    INIT --> QUEUE[Add origin to BFS queue]
    QUEUE --> POP[Pop node from queue]
    POP --> ITER[Iterate over dependents]
    ITER --> CHECK{All strong deps<br/>of dependent failed?}
    CHECK -->|Yes| ADD[Add dependent to failed set]
    ADD --> APPEND[Append to propagation path]
    APPEND --> ENQUEUE[Add dependent to queue]
    CHECK -->|No| SKIP[Skip dependent]
    ENQUEUE --> QUEUE
    SKIP --> QUEUE
    QUEUE --> DONE{Queue empty?}
    DONE -->|No| POP
    DONE -->|Yes| RESULT[Return FailureResult]
```

### Key Metrics

| Metric | Method | Description |
|--------|--------|-------------|
| Blast Radius | `simulate_failure(node_id)` | Total nodes affected by a single failure |
| Impact Percentage | `impact_percentage(failed_nodes)` | % of total network capacity lost |
| Critical Nodes | `critical_nodes()` | Nodes ranked by blast radius (descending) |
| SPOFs | `single_points_of_failure()` | Nodes whose failure cascades to ≥1 other node |
| Worst Case | `worst_case_failure()` | Node producing the largest blast radius |
| Resilience Score | `resilience_score()` | 1.0 = no SPOFs, 0.0 = every node is a SPOF |
| Effective Capacity | `effective_capacity(node_id)` | Capacity adjusted for node status |

### Conjunctive Propagation Example

```mermaid
graph TD
    subgraph Redundant["Redundant Node (Survives)"]
        G1[Gen 1 ✅] --> P[Pump 1]
        G2[Gen 2 ✅] --> P
    end

    subgraph NonRedundant["Non-Redundant Node (Fails)"]
        G3[Gen 3 ❌] --> H[Hospital 1]
    end

    style G1 fill:#51cf66,color:#fff
    style G2 fill:#51cf66,color:#fff
    style G3 fill:#ff6b6b,color:#fff
    style P fill:#51cf66,color:#fff
    style H fill:#ff6b6b,color:#fff
```

- **Pump 1** has two strong dependencies (Gen 1, Gen 2). Losing one does NOT cause failure.
- **Hospital 1** has one strong dependency (Gen 3). Losing it causes immediate failure.

---

## Self-Healing Framework

The self-healing framework combines **circuit breakers**, **health monitoring**, and **automatic failover** to detect and recover from component failures without human intervention.

```mermaid
stateDiagram-v2
    [*] --> CLOSED: Component healthy
    CLOSED --> CLOSED: Success (reset count)
    CLOSED --> OPEN: failure_count >= threshold
    OPEN --> HALF_OPEN: recovery_timeout elapsed
    HALF_OPEN --> CLOSED: Probe succeeds
    HALF_OPEN --> OPEN: Probe fails
    OPEN --> [*]: All failovers exhausted
```

### Self-Healing Engine Flow

```mermaid
flowchart TD
    MON[Health Monitor<br/>check_health] -->|UNHEALTHY| CB[Circuit Breaker<br/>state → OPEN]
    MON -->|HEALTHY| OK[Circuit Breaker<br/>state → CLOSED]
    CB --> FM[Failover Manager<br/>failover to backup]
    FM -->|Success| ACTIVE[Active component<br/>switched to backup]
    FM -->|Exhausted| ALERT[Alert: no more backups]
    OK --> RESTORE[Failover Manager<br/>restore primary]
    RESTORE --> ACTIVE2[Active component<br/>restored to primary]
```

### Component Classes

| Class | Responsibility |
|-------|---------------|
| `CircuitBreaker` | Blocks calls after repeated failures; CLOSED → OPEN → HALF_OPEN → CLOSED |
| `HealthMonitor` | Tracks component health status (HEALTHY / UNHEALTHY) |
| `FailoverManager` | Manages ordered failover to backup components |
| `SelfHealingEngine` | Orchestrates all three; `monitor()` triggers detection + recovery |

### Self-Healing Engine API

```python
engine = SelfHealingEngine()
engine.register_component("GEN-1", backups=["GEN-2", "GEN-3"], check=health_check_fn)
engine.monitor("GEN-1")  # Detects failure, opens circuit, fails over
# ... later ...
engine.monitor("GEN-1")  # Detects recovery, closes circuit, restores primary
```

---

## NIST / CISA Compliance

Apex Resilience Grid provides dual compliance engines:

### NIST AI 100-2 (Adversarial Machine Learning)

```mermaid
graph LR
    subgraph Risk["Risk Identification"]
        R1[Data Poisoning]
        R2[Evasion Attack]
        R3[Privacy Leakage]
        R4[Model Abuse]
    end

    subgraph Controls["Governance Controls"]
        C1[Data Validation]
        C2[Model Monitoring]
        C3[Access Control]
        C4[Encryption at Rest]
    end

    subgraph Report["Compliance Report"]
        S[Summary]
        FB[Function Breakdown]
        G[Gap Analysis]
        H[SHA-256 Hash]
    end

    R1 -->|mitigated by| C1
    R2 -->|mitigated by| C2
    R3 -->|mitigated by| C3
    R4 -->|mitigated by| C4
    C1 --> S
    C2 --> S
    C3 --> S
    C4 --> S
    S --> FB
    S --> G
    S --> H
```

### CISA CSF v2.0 Alignment

```mermaid
graph TB
    subgraph CSF["CISA Cybersecurity Framework v2.0"]
        G[GOVERN<br/>12 controls]
        I[IDENTIFY<br/>8 controls]
        P[PROTECT<br/>15 controls]
        D[DETECT<br/>8 controls]
        R[RESPOND<br/>10 controls]
        RC[RECOVER<br/>8 controls]
    end

    G -->|critical| Score[Overall Score]
    I -->|high| Score
    P -->|medium| Score
    D -->|high| Score
    R -->|high| Score
    RC -->|low| Score
```

### Compliance Engine Features

| Feature | Module | Description |
|---------|--------|-------------|
| Audit Trail | `ComplianceEngine` | Timestamped, actor-attributed action log |
| Blast-Radius Isolation | `ComplianceEngine.get_isolation_points()` | Identifies key isolation nodes from cascade results |
| NIST AI Risk Tracking | `nist_compliance.py` | AIRisk, GovernanceControl, ComplianceReport |
| CISA CSF Catalog | `cisa_compliance.py` | 61 controls across 6 functions |
| Gap Analysis | `GapAnalysis` | Identifies unimplemented controls with severity |
| Report Export | `ComplianceEngine.export_audit_log()` | JSON export for auditors |

### Audit Trail Entry Schema

```json
{
  "timestamp": "2026-10-01T12:00:00+00:00",
  "action": "pipeline_start",
  "actor": "system",
  "details": { "grid_name": "test-grid" }
}
```

---

## SCADA / ICS Integration

The SCADA module provides industrial control system monitoring, OT/IT gateway integration, and statistical anomaly detection.

```mermaid
graph TB
    subgraph OT["OT Network (Level 0-2)"]
        PLC[PLC-001<br/>Modbus]
        RTU[RTU-001<br/>DNP3]
        SENS[SENS-001<br/>OPC-UA]
    end

    subgraph DMZ["DMZ / Data Diode"]
        GW[OT/IT Gateway]
        DD[Data Diode<br/>OT→IT only]
    end

    subgraph IT["IT Network (Level 3-4)"]
        MON[SCADA Monitor]
        AN[Anomaly Detector]
        HMI[HMI / Dashboard]
    end

    PLC -->|Readings| GW
    RTU -->|Readings| GW
    SENS -->|Readings| GW
    GW -->|OT→IT| DD
    DD --> MON
    MON --> AN
    AN -->|Alarms| HMI
```

### SCADA System Components

| Class | Description |
|-------|-------------|
| `SCADAMonitor` | Device registry, threshold-based alarm generation |
| `AnomalyDetector` | Statistical anomaly detection (rate-of-change, pattern deviation, threshold breach, communication loss) |
| `OTITGateway` | Secure OT/IT data exchange with protocol translation and data diode |
| `SCADASystem` | Integrated system combining all three |

### Supported Protocols

| Protocol | Type | Use Case |
|----------|------|----------|
| Modbus | Serial/TCP | PLCs, RTUs |
| DNP3 | Serial/TCP | SCADA remote units |
| OPC-UA | TCP | Industrial interoperability |
| IEC 60870 | TCP | Telecontrol |
| MQTT | TCP | IoT sensor telemetry |

### Anomaly Detection Types

```mermaid
flowchart LR
    R[SCADA Reading] --> AD[Anomaly Detector]
    AD -->|Rate of change > threshold| A1[Rate-of-Change Anomaly]
    AD -->|Deviation > 3σ from mean| A2[Pattern Deviation]
    AD -->|Value outside [low, high]| A3[Threshold Breach]
    AD -->|No comm for > threshold| A4[Communication Loss]
```

### OT/IT Gateway Data Diode

```mermaid
sequenceDiagram
    participant OT as OT Network
    participant GW as OT/IT Gateway
    participant IT as IT Network

    Note over GW: Data Diode ENABLED
    OT->>GW: sensor_data (OT→IT)
    GW->>IT: forwarded ✅
    IT->>GW: command (IT→OT)
    GW--xIT: BLOCKED ❌ (PermissionError)
```

---

## Digital Twin

The `DigitalTwin` provides real-time infrastructure modeling, simulation, and predictive analysis.

```mermaid
graph TB
    subgraph Physical["Physical Infrastructure"]
        P1[Power Plant]
        P2[Substation]
        P3[Load]
    end

    subgraph Twin["Digital Twin"]
        T1[Node: gen1<br/>capacity: 100<br/>load: 80<br/>health: 0.9]
        T2[Node: sub1<br/>capacity: 100<br/>load: 60<br/>health: 0.8]
        T3[Node: load1<br/>capacity: 50<br/>load: 40<br/>health: 1.0]
        E1[Edge: gen1→sub1]
        E2[Edge: sub1→load1]
    end

    subgraph Analytics["Predictive Analytics"]
        PR[Failure Probability]
        TTF[Time to Failure]
        VULN[Vulnerable Components]
        SIM[Cascade Simulation]
    end

    P1 -.->|mirrors| T1
    P2 -.->|mirrors| T2
    P3 -.->|mirrors| T3
    T1 --> PR
    T2 --> PR
    T3 --> PR
    T1 --> TTF
    T2 --> TTF
    T1 --> VULN
    T2 --> VULN
    T1 --> SIM
    T2 --> SIM
    T3 --> SIM
```

### Digital Twin Capabilities

| Capability | Method | Description |
|------------|--------|-------------|
| Node Management | `add_node()`, `remove_node()` | CRUD for infrastructure nodes |
| Edge Management | `add_edge()` | Connect nodes with weighted edges |
| Load Tracking | `update_node_load()` | Real-time load updates |
| Health Monitoring | `degrade_health()`, `repair()` | Health score 0.0–1.0 |
| Critical Nodes | `get_critical_nodes(threshold)` | Nodes with load_ratio ≥ threshold |
| Cascade Simulation | `simulate_cascading_failure(node_id)` | BFS failure propagation |
| Failure Prediction | `predict_failure_probability(node_id)` | Load × 0.6 + Health × 0.4 |
| Time to Failure | `predict_time_to_failure(node_id)` | Estimated time until failure |
| State Snapshot | `snapshot_state()` / `restore_state()` | Save/restore twin state |
| Load Simulation | `simulate_load_increase(node_id, increase)` | What-if overload analysis |
| Topology Summary | `get_topology_summary()` | Node/edge counts by type |

### Failure Prediction Model

```mermaid
graph LR
    L[Load Ratio] -->|× 0.6| P[Failure Probability]
    H[Health Factor<br/>1.0 - health] -->|× 0.4| P
    P --> RL{Risk Level}
    RL -->|≥ 0.7| CR[CRITICAL]
    RL -->|≥ 0.4| MED[MEDIUM]
    RL -->|< 0.4| LOW[LOW]
```

---

## Zero-Trust Architecture

The zero-trust engine implements **micro-segmentation**, **identity verification**, and **least-privilege access** with default-deny policies.

```mermaid
graph TB
    subgraph Segments["Network Segments (Default Deny)"]
        S1[Energy Segment<br/>zone: critical]
        S2[Water Segment<br/>zone: critical]
        S3[Transport Segment<br/>zone: operational]
        S4[Emergency Segment<br/>zone: critical]
    end

    subgraph Identity["Identity Layer"]
        I1[Device Identity<br/>certificate + MFA]
        I2[User Identity<br/>certificate + MFA]
        I3[Service Identity<br/>certificate]
    end

    subgraph Policy["Access Policy Engine"]
        P1[Role: operator<br/>Segment: energy<br/>Perms: read, write]
        P2[Role: viewer<br/>Segment: water<br/>Perms: read]
        P3[Role: contractor<br/>Segment: transport<br/>Perms: read<br/>TTL: 1 hour]
    end

    S1 --> P1
    S2 --> P2
    S3 --> P3
    I1 --> P1
    I2 --> P2
    I3 --> P3
```

### Zero-Trust Enforcement Flow

```mermaid
sequenceDiagram
    participant C as Client
    participant ZT as Zero-Trust Engine
    participant S as Segment

    C->>ZT: authenticate(certificate, mfa_token)
    ZT-->>C: authenticated ✅ + session token

    C->>ZT: authorize(identity, segment, permission)
    ZT->>ZT: check_access(role, segment, permission)
    alt Policy exists and not expired
        ZT-->>C: authorized ✅
    else No policy or expired
        ZT-->>C: AuthorizationError ❌
    end

    C->>S: communicate(src_segment, dst_segment, data)
    S->>S: check egress/ingress rules
    alt Both rules allow
        S-->>C: communication allowed ✅
    else Rule denies
        S-->>C: SegmentIsolationError ❌
    end
```

### Zero-Trust Components

| Class | Description |
|-------|-------------|
| `Segment` | Network segment with explicit ingress/egress rules (default-deny) |
| `Identity` | Verified identity (device, user, or service) with certificate + optional MFA |
| `Role` | Named set of permissions |
| `AccessPolicy` | Maps role → segment with specific permissions + optional TTL |
| `ZeroTrustEngine` | Orchestrates micro-segmentation, identity, and least-privilege policies |

### Security Properties

- **Default Deny**: All ingress/egress denied unless explicitly allowed
- **Just-in-Time Access**: Policies can have TTL for temporary access
- **Permission Boundary**: Role permissions are intersected with policy permissions
- **Session Expiry**: Authenticated sessions expire after TTL
- **MFA Support**: Per-identity MFA requirement

---

## Post-Quantum Cryptography

The PQC module implements NIST FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) for quantum-resistant key exchange and digital signatures.

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Server

    C->>C: Generate Kyber keypair
    C->>C: Generate Dilithium keypair
    C->>S: ClientHello (Kyber PK)

    S->>S: Generate Kyber keypair
    S->>S: Generate Dilithium keypair
    S->>S: Encapsulate shared secret to client PK
    S->>S: Sign handshake with Dilithium
    S->>C: ServerHello (Kyber PK, ciphertext, Dilithium signature)

    C->>C: Decapsulate shared secret
    C->>C: Verify server signature
    C->>C: Derive AES-256-GCM session key
    S->>S: Derive AES-256-GCM session key

    Note over C,S: Encrypted channel established
    C->>S: AES-256-GCM encrypted message
    S->>C: AES-256-GCM encrypted message
```

### PQC Components

| Class | Algorithm | Standard | Key Size |
|-------|-----------|----------|----------|
| `KyberKEM` | ML-KEM-512 | FIPS 203 | PK: 800B, SK: 1632B, CT: 768B |
| `DilithiumSignature` | ML-DSA-44 | FIPS 204 | PK: 1312B, SK: 2560B, Sig: 2420B |
| `QuantumResistantTLS` | Kyber + Dilithium + AES-256-GCM | Composite | Session key: 32B |

### Quantum-Resistant TLS Handshake

```mermaid
flowchart LR
    CH[ClientHello<br/>Kyber PK] --> SH[ServerHello<br/>Kyber PK + CT + Dilithium Sig]
    SH --> DECAPS[Client decapsulates<br/>shared secret]
    DECAPS --> VERIFY[Client verifies<br/>Dilithium signature]
    VERIFY --> DERIVE[Both derive<br/>AES-256-GCM key]
    DERIVE --> ENCRYPT[Encrypted Channel<br/>AES-256-GCM]
```

### Security Features

- **Replay Protection**: Handshake IDs tracked to prevent replay attacks
- **Implicit Rejection**: Wrong Kyber secret key produces different shared secret
- **Authenticated Encryption**: AES-256-GCM with derived session key
- **Tamper Detection**: GCM authentication tag verification

---

## Benchmark Comparisons

### Feature Matrix

| Feature | Apex Resilience Grid | Siemens (MindSphere / SICAM) | GE Digital (Predix / APM) | Schneider Electric (EcoStruxure) | Honeywell (Forge / Experion) |
|---------|---------------------|------------------------------|---------------------------|----------------------------------|-------------------------------|
| **Cross-Domain Orchestration** | ✅ Native 4-domain model | ⚠️ Energy-focused | ⚠️ Energy-focused | ⚠️ Energy + Building | ⚠️ Process-focused |
| **Cascading Failure Analysis** | ✅ Multi-hop conjunctive propagation | ❌ Not available | ⚠️ Limited (single domain) | ❌ Not available | ❌ Not available |
| **Self-Healing / Auto-Failover** | ✅ Circuit breaker + failover | ⚠️ Basic redundancy | ⚠️ Basic redundancy | ⚠️ Basic redundancy | ⚠️ Process-level only |
| **NIST AI 100-2 Compliance** | ✅ Full risk taxonomy | ❌ Not available | ❌ Not available | ❌ Not available | ❌ Not available |
| **CISA CSF v2.0 Alignment** | ✅ 61 controls, 6 functions | ⚠️ Partial | ⚠️ Partial | ⚠️ Partial | ⚠️ Partial |
| **SCADA / ICS Integration** | ✅ 5 protocols + OT/IT gateway | ✅ Native (SICAM) | ✅ Native (Predix) | ✅ Native (EcoStruxure) | ✅ Native (Experion) |
| **Digital Twin** | ✅ Real-time + predictive | ⚠️ Limited | ✅ Strong (Predix APM) | ⚠️ Limited | ⚠️ Limited |
| **Zero-Trust Architecture** | ✅ Micro-segmentation + MFA | ⚠️ Basic RBAC | ⚠️ Basic RBAC | ⚠️ Basic RBAC | ⚠️ Basic RBAC |
| **Post-Quantum Crypto** | ✅ ML-KEM + ML-DSA | ❌ Not available | ❌ Not available | ❌ Not available | ❌ Not available |
| **Event Bus** | ✅ Domain-aware pub/sub | ⚠️ Proprietary | ⚠️ Proprietary | ⚠️ Proprietary | ⚠️ Proprietary |
| **Open Source** | ✅ AGPL-3.0 | ❌ Proprietary | ❌ Proprietary | ❌ Proprietary | ❌ Proprietary |
| **Python-Native** | ✅ Pure Python | ❌ Java/C++ | ❌ Java/C++ | ❌ Java/C++ | ❌ Proprietary |

### Architecture Comparison

```mermaid
graph TB
    subgraph Apex["Apex Resilience Grid"]
        A1[Cross-Domain Event Bus]
        A2[Cascading Failure Analyzer]
        A3[Self-Healing Engine]
        A4[Digital Twin]
        A5[Zero-Trust Engine]
        A6[PQC Module]
        A7[Compliance Engine]
        A1 --- A2 --- A3 --- A4 --- A5 --- A6 --- A7
    end

    subgraph Siemens["Siemens MindSphere / SICAM"]
        S1[IoT Connectivity]
        S2[Energy Analytics]
        S3[SCADA Integration]
        S1 --- S2 --- S3
    end

    subgraph GE["GE Digital Predix / APM"]
        G1[Predix Platform]
        G2[Asset Performance Mgmt]
        G3[Energy Analytics]
        G1 --- G2 --- G3
    end

    subgraph Schneider["Schneider Electric EcoStruxure"]
        SC1[EcoStruxure Platform]
        SC2[Energy Management]
        SC3[Building Management]
        SC1 --- SC2 --- SC3
    end

    subgraph Honeywell["Honeywell Forge / Experion"]
        H1[Forge Platform]
        H2[Experion PKS]
        H3[Process Control]
        H1 --- H2 --- H3
    end
```

### Compliance Coverage Comparison

```mermaid
graph LR
    subgraph NIST["NIST Frameworks"]
        N1[NIST AI 100-2]
        N2[NIST CSF]
        N3[NIST 800-53]
    end

    subgraph CISA["CISA Frameworks"]
        C1[CSF v2.0]
        C2[ICECIP]
        C3[Zero Trust]
    end

    subgraph PQC["Post-Quantum"]
        P1[FIPS 203 ML-KEM]
        P2[FIPS 204 ML-DSA]
    end

    N1 -->|✅ Full| Apex[Apex Resilience Grid]
    N2 -->|⚠️ Partial| Apex
    N3 -->|⚠️ Partial| Apex
    C1 -->|✅ 61 controls| Apex
    C2 -->|⚠️ Partial| Apex
    C3 -->|✅ Full| Apex
    P1 -->|✅ ML-KEM-512| Apex
    P2 -->|✅ ML-DSA-44| Apex

    N1 -->|❌| Siemens[Siemens]
    N1 -->|❌| GE[GE Digital]
    N1 -->|❌| Schneider[Schneider]
    N1 -->|❌| Honeywell[Honeywell]
```

### Key Differentiators

| Capability | Apex | Competitors |
|------------|------|-------------|
| **Cross-domain cascade analysis** | Native multi-hop with conjunctive propagation | Single-domain or unavailable |
| **Self-healing with circuit breakers** | Full implementation | Basic redundancy only |
| **Post-quantum cryptography** | ML-KEM + ML-DSA (NIST standards) | Not available |
| **NIST AI 100-2 risk taxonomy** | Full attack category coverage | Not available |
| **CISA CSF v2.0 control catalog** | 61 controls with gap analysis | Partial or unavailable |
| **Open source** | AGPL-3.0 | Proprietary licenses |
| **Python-native** | Pure Python, stdlib-only core | Java/C++/proprietary |

---

## Installation

```bash
git clone https://github.com/your-org/Apex_Resilience_Grid.git
cd Apex_Resilience_Grid
pip install -e .
```

### Dependencies

- **Core**: Python 3.10+ (stdlib only)
- **PQC**: `pqcrypto`, `cryptography`
- **Testing**: `pytest`

## Quick Start

```python
from src.grid.models import Grid, Node, Dependency
from src.grid.pipeline import ResiliencePipeline

# 1. Build a multi-domain grid
grid = Grid("city-grid")
grid.add_node(Node("power-plant-1", "energy", capacity=100))
grid.add_node(Node("substation-1", "energy", capacity=80))
grid.add_node(Node("water-plant-1", "water", capacity=50))
grid.add_node(Node("hospital-1", "emergency", capacity=20))
grid.add_dependency(Dependency("substation-1", "power-plant-1"))
grid.add_dependency(Dependency("water-plant-1", "substation-1"))
grid.add_dependency(Dependency("hospital-1", "substation-1"))

# 2. Run full resilience analysis
pipeline = ResiliencePipeline(grid)
report = pipeline.run_full_analysis()

# 3. Inspect results
print(f"Resilience Score: {report['resilience_score']}/100")
print(f"Critical Nodes: {report['critical_nodes']}")
print(f"Max Blast Radius: {report['summary']['max_blast_radius']}")
print(f"Compliance Status: {report['compliance_status']}")
```

### Event Bus Example

```python
from src.grid.event_bus import EventBus, EntityResolver, Domain, DomainEntity

resolver = EntityResolver()
resolver.register(DomainEntity("feeder-1", Domain.ENERGY, "North Feeder"))

bus = EventBus(resolver=resolver)
bus.subscribe("asset.failure", lambda ev: print(f"Failure: {ev.entity_refs}"))
bus.publish(Event("asset.failure", Domain.ENERGY, entity_refs=["energy:feeder-1"]))
```

### Self-Healing Example

```python
from src.grid.self_healing import SelfHealingEngine

engine = SelfHealingEngine()
engine.register_component("GEN-1", backups=["GEN-2"], check=lambda: False)
engine.monitor("GEN-1")  # Detects failure, opens circuit, fails over to GEN-2
```

### PQC Example

```python
from src.grid.pqc import QuantumResistantTLS

client = QuantumResistantTLS()
server = QuantumResistantTLS()

# Quantum-resistant handshake
client_hello = client.initiate_handshake()
server_hello = server.respond_to_handshake(client_hello)
client.complete_handshake(server_hello)

# Encrypted communication
ciphertext = client.encrypt(b"secret grid command")
plaintext = server.decrypt(ciphertext)
```

## Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src

# Run specific test file
pytest tests/test_cascading.py -v
```

### Test Coverage

| Module | Test File | Tests |
|--------|-----------|-------|
| Event Bus | `test_event_bus.py` | 25+ tests |
| Cascading Failure | `test_cascading.py` | 25+ tests |
| Self-Healing | `test_self_healing.py` | 15+ tests |
| CISA Compliance | `test_cisa_compliance.py` | 20+ tests |
| NIST Compliance | `test_nist_compliance.py` | 25+ tests |
| SCADA | `test_scada.py` | 30+ tests |
| Digital Twin | `test_digital_twin.py` | 30+ tests |
| Zero-Trust | `test_zero_trust.py` | 20+ tests |
| PQC | `test_pqc.py` | 20+ tests |
| Integration | `test_resilience.py` | 20+ tests |

## License

AGPL-3.0
