# Aegis — Architecture Overview

```mermaid
graph TD
    CLI["CLI (aegis scan)"] --> ORC["ScanOrchestrator"]
    API["REST API (FastAPI)"] --> ORC

    ORC --> AUTH["AuthorizationSystem"]
    ORC --> RL["RateLimiter"]
    ORC --> AUDIT["ImmutableAuditLog"]
    ORC --> SR["ScanResult + ReportGenerator"]

    ORC -->|asyncio.gather| S1["PromptInjection\nScanners"]
    ORC -->|asyncio.gather| S2["ActionSecurity\nScanners"]
    ORC -->|asyncio.gather| S3["StaticAnalysis\nScanners"]
    ORC -->|asyncio.gather| S4["DataPrivacy\nScanners"]

    S1 --> PI["direct_injection\nindirect_injection\ndefense_validator"]
    S2 --> AS["tool_misuse\nhitl_bypass\nprivilege_escalation"]
    S3 --> SA["aibom_generator\nconfig_analyzer"]
    S4 --> DP["data_leakage\ncontext_isolation"]

    ORC -->|optional| SIM["AgentSimulation\n(sandbox + hitl_validator)"]

    S1 & S2 --> ATK["AttackLibrary\n(GeneticFuzzer, LLMGenerator)"]

    SR --> RPT["Markdown / JSON / SARIF"]

    classDef security fill:#831,color:#fff
    class AUTH,RL,AUDIT security
```

## Component Layers

| Layer | Package | Purpose |
|---|---|---|
| **Orchestration** | `aegis.core.orchestrator` | Runs all scanners concurrently, aggregates findings |
| **Scanners** | `aegis.scanners.*` | Domain-specific security checks |
| **Agent Simulation** | `aegis.scanners.agent_simulation` | Docker sandbox + HITL bypass probing |
| **Attack Library** | `aegis.attack_library` | Genetic fuzzer + LLM generator for adversarial prompts |
| **Threat Modelling** | `aegis.core.threat_model` | STRIDE-AI analysis of agent manifests |
| **Reporting** | `aegis.reporting` | Markdown, JSON, SARIF 2.1.0 output |
| **Security** | `aegis.security` | Auth, rate limiting, audit log |
| **API** | `aegis.api` | FastAPI REST interface |

## Data Flow

```
AgentManifest
     │
     ▼
ThreatModeler ──► attack surface + trust boundaries
     │
     ▼
ScanOrchestrator
     ├── [concurrent] all scanners ──► Finding[]
     │       │
     │       └── each scanner optionally calls _send_to_agent()
     │               ├── live mode:  HTTP POST → target_endpoint
     │               └── sim mode:   returns ""
     │
     ▼
ScanResult ──► ReportGenerator ──► Markdown / JSON / SARIF
```

## Key Design Decisions

- **Simulation-first**: All scanners work without a live agent via graceful fallback in `_send_to_agent()`.
- **Elitism GA**: The genetic fuzzer uses 20% elitism so the best attack prompts survive across generations.
- **SARIF output**: CI/CD integration via SARIF 2.1.0 → GitHub Code Scanning / `upload-sarif` action.
- **Immutable audit trail**: Blockchain-style hash chaining in SQLite for tamper evidence.
