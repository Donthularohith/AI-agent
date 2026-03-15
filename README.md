# 🛡️ AI Agent Identity Governance Platform

> **Enterprise-grade governance for AI agent identities, credentials, permissions, and behavior.**  
> Built for healthcare environments with HIPAA, NIST AI RMF, and EU AI Act compliance.

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.109+-green.svg)](https://fastapi.tiangolo.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Tech Stack](#tech-stack)
- [Quick Start](#quick-start)
- [Build Guide](#build-guide)
- [API Reference](#api-reference)
- [Attack Simulations](#attack-simulations)
- [SOC Dashboard](#soc-dashboard)
- [Testing](#testing)
- [Compliance Mapping](#compliance-mapping)
- [Author](#author)

---

## Overview

As AI agents (powered by LangChain, CrewAI, AutoGen, etc.) proliferate in enterprise environments, they create a **Non-Human Identity (NHI) management crisis**. Each agent needs:

- **Registered identity** with purpose, scope, and ownership
- **Short-lived, purpose-bound credentials** (not hardcoded API keys)
- **Least-privilege tool access** enforced at runtime
- **Behavioral monitoring** to detect compromise or drift
- **Immutable audit trails** for compliance

This platform solves all of these with a defense-in-depth architecture.

### Key Features

| Feature | Description |
|---------|-------------|
| 🏢 **Agent Registry** | Centralized NHI inventory with lifecycle management |
| 🔐 **Vault-Backed Credentials** | Short-lived tokens via HashiCorp Vault AppRole |
| 📜 **OPA Policy Engine** | Real-time Rego policy evaluation for every action |
| 🧠 **Behavioral Monitoring** | Per-agent Isolation Forest anomaly detection |
| ⚡ **Circuit Breaker** | Auto-suspend on repeated policy violations |
| 🔗 **Delegation Chain** | Parent→child scope reduction enforcement |
| 📊 **SOC Dashboard** | 4-tab Streamlit dashboard for security operations |
| 🔍 **Splunk Integration** | Async batch HEC forwarding for SIEM correlation |
| 📝 **Immutable Audit Log** | PostgreSQL append-only with DB-level triggers |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    SOC Dashboard (Streamlit)                  │
│   Agent Fleet │ Live Anomalies │ Audit Trail │ Blast Radius  │
└────────────────────────┬────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────┐
│                  FastAPI Governance API                      │
│  /agents  │  /credentials  │  /policy  │  /audit  │ /health │
├──────┬──────────┬──────────┬───────────┬──────────┬─────────┤
│      │          │          │           │          │         │
│  Registry   Vault TM   OPA Client  Behavioral  Circuit    │
│   (CRUD)    (Creds)    (Policy)    Monitor     Breaker    │
│      │          │          │        (IF ML)    (Enforce)   │
├──────┴──────────┴──────────┴───────────┴──────────┴─────────┤
│                    Audit Logger + Splunk HEC                 │
├─────────────────────────────────────────────────────────────┤
│  PostgreSQL     │   HashiCorp Vault   │   OPA Server       │
│  (append-only)  │   (KV v2 secrets)   │   (Rego policies)  │
└─────────────────┴─────────────────────┴────────────────────┘
```

**Six Defense Layers:**

1. **Agent Registry** — Identity inventory with lifecycle states
2. **Credential Lifecycle Manager** — Vault-backed short-lived tokens
3. **Policy Engine** — OPA Rego policies for real-time authorization
4. **Behavioral Monitor** — Isolation Forest anomaly detection (12-feature vector)
5. **Runtime Enforcement** — Circuit breaker + MCP interceptor + delegation chain
6. **Audit & Compliance** — Immutable logs + Splunk HEC forwarding

---

## Tech Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| API | FastAPI + Uvicorn | Async REST API with auto-docs |
| Database | PostgreSQL 15 + SQLAlchemy 2.0 | Agent registry + immutable audit log |
| Secrets | HashiCorp Vault 1.15 | Dynamic credential issuance |
| Policy | Open Policy Agent 0.60 | Rego policy evaluation |
| ML | scikit-learn (Isolation Forest) | Per-agent behavioral baselines |
| Dashboard | Streamlit | SOC single-pane-of-glass |
| SIEM | Splunk HEC | Async event forwarding |
| Container | Docker + Docker Compose | Local development |

---

## Quick Start

### Prerequisites

- Docker Desktop (v4.0+)
- Python 3.11+
- Git

### Option 1: Docker Compose (Recommended)

```bash
# Clone the repository
git clone https://github.com/rohithdonthula/ai-agent-governance.git
cd ai-agent-governance

# Start all services
docker-compose up -d

# Check health
curl http://localhost:8000/health

# Seed demo agents
python -m scripts.seed_demo_agents

# Open SOC dashboard
open http://localhost:8501

# Run attack simulation
python -m scripts.simulate_attack
```

### Option 2: Local Development

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Copy environment config
cp .env.example .env

# Start dependencies (PostgreSQL, Vault, OPA)
# PostgreSQL: brew install postgresql && brew services start postgresql
# Vault: vault server -dev -dev-root-token-id=dev-root-token
# OPA: opa run --server --addr=localhost:8181

# Initialize database and start API
uvicorn api.main:app --reload --host 0.0.0.0 --port 8000

# In another terminal: Start dashboard
streamlit run dashboard/app.py
```

---

## Build Guide

### Phase 1: Foundation (Registry + Database)

```
registry/
├── database.py    — Async SQLAlchemy engine + session factory
├── models.py      — Agent, AuditLog, AnomalyEvent models
├── schemas.py     — Pydantic v2 request/response validation
└── crud.py        — All database operations
```

**Key Design Decisions:**
- Async SQLAlchemy 2.0 with asyncpg for non-blocking DB access
- Append-only audit log enforced by PostgreSQL trigger (not application code)
- JSONB columns for flexible tool/resource/compliance lists
- UUID primary keys for distributed ID generation

### Phase 2: Credential Lifecycle (Vault Integration)

```
credentials/
├── vault_client.py    — hvac client with AppRole auth
└── token_manager.py   — Token issuance, rotation, revocation
```

**Key Design Decisions:**
- AppRole auth for machine-to-machine (not root token in production)
- Zero-downtime rotation: new credential issued before old is revoked
- Credentials scoped to agent's declared resources
- Raw secrets never logged or returned in API responses

### Phase 3: Policy Engine (OPA + Rego)

```
policy/
├── opa_client.py           — Async REST client for OPA
├── policy_loader.py        — Hot-reload Rego policies
└── policies/
    ├── agent_authz.rego     — Main 5-check authorization policy
    ├── delegation.rego      — Delegation chain constraints
    └── tool_allowlist.rego  — MCP tool URI enforcement
```

**Key Design Decisions:**
- Fail-closed: deny access if OPA is unreachable
- Local fallback evaluation for resilience
- Hot-reload without service restart (FR-019)
- Connection pooling for <50ms p99 latency target

### Phase 4: Behavioral Monitoring (ML Pipeline)

```
monitoring/
├── feature_extractor.py    — 12-feature behavioral vector
├── baseline_trainer.py     — Per-agent Isolation Forest models
├── behavioral_monitor.py   — Orchestration pipeline
└── alert_engine.py         — Severity classification + recommendations
```

**The 12-Feature Vector:**

| # | Feature | MITRE Indicator |
|---|---------|-----------------|
| 1 | tool_call_count | Volume anomaly |
| 2 | unique_resource_count | Breadth of access |
| 3 | out_of_hours_flag | Temporal anomaly |
| 4 | new_tool_flag | Tool discovery |
| 5 | resource_entropy | Scanning/reconnaissance |
| 6 | delegation_spawns | Amplification attack |
| 7 | failed_auth_count | Credential probing |
| 8 | data_volume_bytes | Exfiltration |
| 9 | api_error_rate | Probing/malfunction |
| 10 | cross_tenant_flag | Lateral movement |
| 11 | privilege_escalation_attempts | Vertical escalation |
| 12 | time_since_last_activity | Dormancy |

### Phase 5: Runtime Enforcement

```
enforcement/
├── circuit_breaker.py      — Per-agent sliding window kill switch
├── mcp_interceptor.py      — Inline tool call governance wrapper
└── delegation_chain.py     — Scope reduction validator
```

### Phase 6: Audit & Integration

```
audit/
├── audit_logger.py   — Dual-write to PostgreSQL + Splunk
└── splunk_client.py  — Async batch HEC forwarding
```

---

## API Reference

### Agent Registry

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/agents` | Register new agent |
| GET | `/agents` | List all agents (paginated) |
| GET | `/agents/{id}` | Get agent details |
| POST | `/agents/{id}/suspend` | Suspend agent + cascade |
| POST | `/agents/{id}/revoke` | Permanently revoke agent |
| POST | `/agents/{id}/reactivate` | Reactivate suspended agent |

### Credentials

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/credentials/issue` | Issue short-lived credential |
| POST | `/credentials/rotate` | Zero-downtime rotation |
| POST | `/credentials/revoke/{id}` | Immediate revocation |

### Policy

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/policy/decide` | Evaluate OPA authorization |
| POST | `/policy/reload` | Hot-reload all policies |
| GET | `/policy/list` | List available policies |

### Audit

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/audit/agents/{id}` | Paginated audit log |
| GET | `/audit/anomalies` | Recent anomaly events |
| POST | `/audit/anomalies/{id}/resolve` | Resolve anomaly |

### Health

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Full dependency health check |
| GET | `/health/live` | Kubernetes liveness probe |
| GET | `/health/ready` | Kubernetes readiness probe |

**Full interactive docs:** http://localhost:8000/docs

---

## Attack Simulations

Run the attack simulation to demonstrate platform defenses:

```bash
python -m scripts.simulate_attack
```

### Scenario 1: Tool Allowlist Violation
- **MITRE ATT&CK:** T1210 (Exploitation of Remote Services)
- Agent tries `mcp://emr/admin/delete` (not in allowlist)
- **Result:** OPA denies, action logged to audit trail

### Scenario 2: Delegation Chain Escalation
- **MITRE ATT&CK:** T1078 + T1134
- Child agent requests broader scope than parent
- **Result:** Delegation validator rejects registration

### Scenario 3: Circuit Breaker Trigger
- **MITRE ATT&CK:** T1498 + T1499
- Rapid-fire unauthorized requests exceed threshold
- **Result:** Circuit breaker trips, agent auto-suspended

---

## SOC Dashboard

Access at http://localhost:8501

| Tab | Purpose |
|-----|---------|
| 📊 Agent Fleet | Overview of all registered agents with status, quick suspend action |
| 🚨 Live Anomalies | Real-time anomaly feed with severity, scores, and feature vectors |
| 📜 Audit Timeline | Per-agent action history with outcome distribution charts |
| 💥 Blast Radius | Impact assessment for potentially compromised agents |

---

## Testing

```bash
# Run all tests
pytest tests/ -v

# Run specific test modules
pytest tests/test_registry.py -v
pytest tests/test_enforcement.py -v
pytest tests/test_monitoring.py -v

# Run with coverage
pytest tests/ --cov=. --cov-report=html
```

---

## Compliance Mapping

| Framework | Coverage |
|-----------|----------|
| **NIST AI RMF** | GOVERN, MAP, MEASURE, MANAGE functions |
| **NIST SP 800-63** | IAL2/AAL2 agent identity assurance |
| **EU AI Act** | Article 9 (risk management), Article 13 (transparency) |
| **HIPAA** | PHI access controls, audit trail, breach detection |
| **OWASP Agentic AI 2026** | NHI governance, tool abuse, delegation chain |
| **PCI DSS** | Credential rotation, access logging |

---

## Project Structure

```
ai-agent-governance/
├── api/
│   ├── main.py                  # FastAPI application
│   ├── routers/
│   │   ├── agents.py            # Agent CRUD endpoints
│   │   ├── credentials.py       # Credential lifecycle
│   │   ├── policy.py            # OPA decision endpoint
│   │   ├── audit.py             # Audit log queries
│   │   └── health.py            # Health probes
│   └── middleware/
│       ├── auth.py              # JWT authentication
│       └── rate_limit.py        # Request throttling
├── registry/
│   ├── database.py              # Async SQLAlchemy engine
│   ├── models.py                # Agent, AuditLog, AnomalyEvent
│   ├── schemas.py               # Pydantic v2 schemas
│   └── crud.py                  # Database operations
├── credentials/
│   ├── vault_client.py          # HashiCorp Vault integration
│   └── token_manager.py         # Token lifecycle
├── policy/
│   ├── opa_client.py            # OPA REST client
│   ├── policy_loader.py         # Rego policy loader
│   └── policies/
│       ├── agent_authz.rego     # Main authorization policy
│       ├── delegation.rego      # Delegation constraints
│       └── tool_allowlist.rego  # Tool URI enforcement
├── monitoring/
│   ├── feature_extractor.py     # 12-feature behavioral vector
│   ├── baseline_trainer.py      # Per-agent Isolation Forest
│   ├── behavioral_monitor.py    # Monitoring orchestrator
│   └── alert_engine.py          # Alert generation
├── enforcement/
│   ├── circuit_breaker.py       # Sliding window kill switch
│   ├── mcp_interceptor.py       # MCP tool call wrapper
│   └── delegation_chain.py      # Scope reduction validator
├── audit/
│   ├── audit_logger.py          # Dual-write audit service
│   └── splunk_client.py         # Async Splunk HEC client
├── dashboard/
│   └── app.py                   # Streamlit SOC dashboard
├── tests/
│   ├── conftest.py              # Pytest fixtures
│   ├── test_registry.py
│   ├── test_credentials.py
│   ├── test_policy.py
│   ├── test_monitoring.py
│   ├── test_enforcement.py
│   └── test_audit.py
├── scripts/
│   ├── seed_demo_agents.py      # Demo agent seeder
│   └── simulate_attack.py       # Attack simulation
├── PRD.md                       # Product Requirements Document
├── ARCHITECTURE.md              # System Architecture Document
├── requirements.txt
├── docker-compose.yml
├── Dockerfile
├── Dockerfile.dashboard
├── .env.example
└── README.md
```

---

## Author

**Rohith Donthula**  
Cyber Security Analyst | SIEM Engineer | AI Security Researcher

- 3+ years in cybersecurity operations
- Experience with Splunk, QRadar, CrowdStrike, HIPAA/NIST compliance
- Building the bridge between traditional SOC operations and AI agent governance

---

## License

MIT License — see [LICENSE](LICENSE) for details.
