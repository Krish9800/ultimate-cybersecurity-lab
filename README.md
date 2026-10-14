# Ultimate Cybersecurity Lab
### Unified Enterprise Cyber Range & Security Operations Ecosystem

[![CI Pipeline](https://github.com/cybersecurity-engineering/ultimate-cybersecurity-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/cybersecurity-engineering/ultimate-cybersecurity-lab/actions)
[![Python Version](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Type Checked](https://img.shields.io/badge/type--checked-mypy%20strict-brightgreen.svg)](https://mypy.readthedocs.io/)
[![Security: Bandit](https://img.shields.io/badge/security-bandit%20passed-brightgreen.svg)](https://github.com/PyCQA/bandit)

The **Ultimate Cybersecurity Lab** is an enterprise-grade virtual cyber range simulation platform, adversary campaign emulator, detection evaluation hub, and resilience scoring engine. It models realistic multi-subnet enterprise networks, executes end-to-end multi-phase adversary campaigns mapped to MITRE ATT&CK, evaluates blue team detection rules, injects chaos anomalies, and produces quantitative resilience analytics.

---

## Overview

Modern cybersecurity operations require testing defenses against realistic, multi-stage adversary tradecraft across partitioned enterprise network boundaries. Traditional hypervisor-based labs are resource-heavy and slow to spin up, while mock scripts lack routing reality, stateful firewall inspection, and telemetry correlation.

The **Ultimate Cybersecurity Lab** bridges this gap by delivering a lightweight, mathematically sound discrete-event cyber range ecosystem featuring:
- A **Multi-Subnet Virtual Topology Engine** with stateful firewall ACLs, VLANs, and longest-prefix-match routing.
- A **Full Kill-Chain Attack Campaign Emulator** chaining MITRE ATT&CK techniques across network zones.
- A **Unified Telemetry & Detection Hub** aggregating NIDS, EDR, IdP, and firewall sensors.
- A **Resilience Scoring Engine** computing a unified Resilience Index (0.0–100.0), MTTD, MTTR, and gap analytics.
- A **Chaos Engineering Engine** injecting dynamic firewall drift, sensor dropouts, and credential exposure.
- A **FastAPI REST Control Plane** and a rich **Typer CLI Dashboard**.

---

## Problem Statement

Enterprise security leadership frequently asks:
1. *If an external attacker compromises our public DMZ web application, how far can they pivot before being contained?*
2. *Do our defensive detection sensors detect the lateral movement before crown-jewel databases are breached?*
3. *What is our Mean Time to Detect (MTTD) and how resilient is our posture under degraded chaos conditions?*

Without a cohesive cyber range ecosystem, security teams cannot answer these questions objectively or quantitatively.

---

## Objectives

1. Model enterprise network topologies with isolated subnets (External, DMZ, Corporate LAN, Secure Enclave, Cloud VPC).
2. Emulate realistic multi-stage adversary campaigns from external reconnaissance to crown-jewel exfiltration.
3. Ingest heterogeneous defensive telemetry across network, endpoint, and identity planes.
4. Calculate rigorous quantitative metrics: Detection Coverage Rate, Containment Rate, MTTD, MTTR, and Resilience Index.
5. Provide developer-friendly interfaces: interactive CLI dashboards, REST APIs, and SQLite WAL storage.

---

## Features

- **Multi-Subnet Virtual Topology Engine**:
  - Discrete-event packet routing with longest-prefix matching.
  - Priority-ordered stateful firewall Access Control Lists (ACLs) with Zero-Trust default deny.
  - Pre-packaged 5-zone Enterprise topology with 7+ virtual hosts and crown-jewel assets.
- **Kill-Chain Attack Campaign Emulator**:
  - Full MITRE ATT&CK technique catalog (`T1595`, `T1046`, `T1190`, `T1059`, `T1003`, `T1558`, `T1021`, `T1560`, `T1048`, `T1486`).
  - Pre-built multi-phase campaigns: *APT Crown-Jewel Data Exfiltration* and *Ransomware Blitzkrieg*.
  - Strict precondition verification and loot harvesting (tokens, Kerberos tickets, exfiltrated archives).
- **Unified Telemetry & Detection Evaluation Hub**:
  - Multi-sensor event synthesis: Network NIDS, Endpoint EDR, Identity IdP, and Firewall logs.
  - Standardized detection rule engine evaluating regex patterns, ports, and event classification.
  - Automated calculation of MTTD and step-by-step detection outcomes (`DETECTED`, `BLOCKED`, `MISSED`).
- **Cyber Range Scoring & Resilience Analytics**:
  - Normalized Resilience Index ($0.0 - 100.0$) with letter grades (A+ through F).
  - Component breakdown: Detection Score, Containment Score, Speed Score, Depth Score, and Crown Jewel Penalty.
  - Automatic identification of defensive gaps and targeted Sigma/EDR remediation rules.
- **Chaos Engineering Engine**:
  - Dynamic injection of firewall rule drift, sensor failures, credential leaks, service crashes, and rogue hosts.
  - Automated or manual recovery with audit tracking.
- **Storage & Interfaces**:
  - Lock-free SQLite Write-Ahead Logging (WAL) persistence for topologies, scenarios, runs, and logs.
  - FastAPI REST control plane with OpenAPI documentation.
  - Rich Typer CLI with terminal dashboards, tabular topology viewers, and scorecard panels.

---

## Architecture

```
                          ┌─────────────────────────────────────┐
                          │         Typer CLI / FastAPI         │
                          └──────────────────┬──────────────────┘
                                             │
                      ┌──────────────────────┴──────────────────────┐
                      │                                             │
                      ▼                                             ▼
        ┌───────────────────────────┐                 ┌───────────────────────────┐
        │  Campaign Emulator (Red)  │                 │   Chaos Runner (Drift)    │
        └─────────────┬─────────────┘                 └─────────────┬─────────────┘
                      │                                             │
                      ▼                                             ▼
        ┌─────────────────────────────────────────────────────────────────────────┐
        │                 Multi-Subnet Virtual Topology Engine                    │
        │      (DMZ, Corporate LAN, Secure Enclave, Cloud VPC, Firewalls)         │
        └─────────────────────────────┬───────────────────────────────────────────┘
                                      │ Emitted Packets & Host Logs
                                      ▼
        ┌─────────────────────────────────────────────────────────────────────────┐
        │                 Unified Telemetry & Detection Hub                       │
        │                (NIDS, EDR, IdP, Firewall Sensors & Rules)               │
        └─────────────────────────────┬───────────────────────────────────────────┘
                                      │ Correlated Alerts & Latencies
                                      ▼
        ┌─────────────────────────────────────────────────────────────────────────┐
        │              Resilience Scoring & Gap Analytics Engine                  │
        │               (Resilience Index 0-100, MTTD, MTTR, Gaps)                │
        └─────────────────────────────┬───────────────────────────────────────────┘
                                      │
                                      ▼
        ┌─────────────────────────────────────────────────────────────────────────┐
        │                   SQLite WAL Persistence Storage                        │
        └─────────────────────────────────────────────────────────────────────────┘
```

---

## Technology Stack

| Category | Technology | Rationale |
| :--- | :--- | :--- |
| **Language** | Python 3.12+ | Native pattern matching, StrEnum, modern typing. |
| **Data Validation** | Pydantic v2.7+ | Immutable schemas (`extra="forbid"`), sub-millisecond parsing. |
| **Settings** | Pydantic-Settings | Environment variable cascading with prefix `CYBERLAB_`. |
| **Web API** | FastAPI + Uvicorn | High-performance ASGI REST control plane with OpenAPI docs. |
| **CLI Framework** | Typer + Rich | Color-coded terminal dashboards, tabular matrices, execution progress. |
| **Database** | SQLite3 (WAL Mode) | Zero-external-dependency, thread-safe, lock-free concurrency. |
| **Testing** | Pytest, Pytest-Cov | Comprehensive unit, integration, and security test suites. |
| **Static Analysis** | Ruff, Mypy Strict, Bandit | Enforces formatting, 100% type safety, and SAST security checks. |
| **Container** | Docker & Compose | Rootless multi-stage build running as non-root user (UID 10001). |

---

## Project Structure

```
ultimate-cybersecurity-lab/
├── .github/workflows/ci.yml         # Automated GitHub Actions CI pipeline
├── Dockerfile                       # Multi-stage rootless container build
├── docker-compose.yml               # Production container orchestration
├── pyproject.toml                   # Project metadata and tool configuration
├── README.md                        # Comprehensive documentation
├── SECURITY.md                      # Vulnerability reporting and ethics
├── CONTRIBUTING.md                  # Developer guidelines and checklist
├── LICENSE                          # MIT License
├── .env.example                     # Environment configuration template
├── .gitignore                       # Git ignore patterns
├── src/cyberlab/
│   ├── config/settings.py           # Pydantic Settings management
│   ├── models/                      # Domain models (Topology, Campaign, Telemetry, Resilience)
│   ├── topology/                    # VirtualRouter, FirewallEngine, TopologyEngine
│   ├── campaign/                    # MITRE ATT&CK Catalog, Scenarios, Emulator
│   ├── telemetry/                   # Sensors, DetectionRuleEngine, TelemetryHub
│   ├── resilience/                  # ResilienceEngine, GapAnalyzer, Metrics
│   ├── chaos/                       # ChaosRunner, AnomalyInjector
│   ├── storage/                     # DatabaseManager (WAL), RangeRepository
│   ├── api/                         # FastAPI app and REST route handlers
│   └── cli/                         # Typer CLI application and Rich formatters
└── tests/
    ├── conftest.py                  # Pytest fixtures and temporary database
    ├── test_config.py               # Settings verification
    ├── test_models.py               # Domain model tests
    ├── test_topology.py             # Router, firewall, and topology tests
    ├── test_campaign.py             # Attack execution tests
    ├── test_telemetry.py            # Telemetry hub and detection rule tests
    ├── test_resilience.py           # Mathematical scoring tests
    ├── test_chaos.py                # Chaos injection and rollback tests
    ├── test_storage.py              # SQLite WAL and repository tests
    ├── test_api.py                  # FastAPI endpoint integration tests
    ├── test_cli.py                  # Typer CLI command tests
    └── test_security.py             # Adversarial security testbed
```

---

## Installation

### Prerequisites
- Linux / WSL Ubuntu
- Python 3.12+
- Git

### Local Setup
```bash
# Clone the repository
cd /home/krish/Github_Projects/ultimate-cybersecurity-lab

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies in editable mode
pip install --upgrade pip
pip install -e ".[dev]"
```

---

## Configuration

Copy `.env.example` to `.env` to customize settings:
```bash
cp .env.example .env
```

| Environment Variable | Default | Description |
| :--- | :--- | :--- |
| `CYBERLAB_ENVIRONMENT` | `development` | Operating environment (`development`, `testing`, `production`). |
| `CYBERLAB_DEBUG` | `false` | Enable verbose debugging traces. |
| `CYBERLAB_DB_PATH` | `cyberlab.db` | File path for SQLite WAL persistence database. |
| `CYBERLAB_WAL_MODE` | `true` | Enable SQLite Write-Ahead Logging. |
| `CYBERLAB_API_HOST` | `127.0.0.1` | REST control plane bind host. |
| `CYBERLAB_API_PORT` | `8000` | REST control plane bind port. |
| `CYBERLAB_DETECTION_WEIGHT` | `0.35` | Resilience weight for Detection Coverage. |
| `CYBERLAB_CONTAINMENT_WEIGHT`| `0.30` | Resilience weight for Zone Containment. |
| `CYBERLAB_SPEED_WEIGHT` | `0.20` | Resilience weight for MTTD latency. |
| `CYBERLAB_DEPTH_WEIGHT` | `0.15` | Resilience weight for Sensor Diversity. |
| `CYBERLAB_CROWN_JEWEL_PENALTY` | `25.0` | Deduction for crown-jewel compromise. |

---

## Usage

### 1. Command Line Interface (CLI)
```bash
# View cyber range topology table
cyberlab topology show

# List virtual hosts and security zones
cyberlab topology hosts

# List available attack campaigns
cyberlab campaign list

# Run full APT Crown-Jewel Exfiltration Campaign
cyberlab campaign run --scenario scenario-apt-exfiltration

# Run Ransomware Blitz Campaign
cyberlab campaign run --scenario scenario-ransomware-blitz

# View post-exercise resilience debrief and gap recommendations
cyberlab resilience report

# Inject a dynamic firewall rule drift chaos drill
cyberlab chaos inject --type FIREWALL_RULE_DRIFT --target fw-010-external-to-dmz-web

# Launch FastAPI REST Control Plane
cyberlab serve --host 127.0.0.1 --port 8000
```

### 2. REST API Control Plane
Launch the REST server:
```bash
cyberlab serve
```
Interactive OpenAPI documentation is available at `http://127.0.0.1:8000/docs`.

Key Endpoints:
- `GET /health`: Health status and range summary.
- `GET /api/v1/topology`: Full topology configuration.
- `GET /api/v1/topology/hosts`: Host states and security zones.
- `POST /api/v1/campaigns/launch`: Execute adversary campaign and return resilience scorecard.
- `GET /api/v1/exercises/{id}`: Detailed exercise debrief report.
- `POST /api/v1/chaos/inject`: Dynamic anomaly injection.

---

## Mathematical Resilience Scoring

The **Resilience Index** ($R_{\text{range}} \in [0.0, 100.0]$) evaluates defensive effectiveness:

$$R_{\text{range}} = w_{\text{det}} \cdot C_{\text{det}} + w_{\text{cont}} \cdot C_{\text{cont}} + w_{\text{time}} \cdot S_{\text{time}} + w_{\text{depth}} \cdot S_{\text{depth}} - P_{\text{blast}}$$

Where:
- $C_{\text{det}}$: Detection Coverage Rate ($\ge 80\%$ target).
- $C_{\text{cont}}$: Zone Containment Percentage ($1 - \frac{N_{\text{breached}}}{N_{\text{total}}}$).
- $S_{\text{time}} = 100 \cdot \exp(-\text{MTTD} / 60.0)$: Exponential speed reward for sub-minute alert latency.
- $S_{\text{depth}}$: Multi-sensor diversity score (NIDS, EDR, IdP, Firewall).
- $P_{\text{blast}}$: Deduction (25.0 pts) if crown-jewel assets are compromised.

---

## Testing & Quality Gates

The test suite covers unit logic, routing, campaign emulation, telemetry, resilience mathematics, persistence, API endpoints, CLI formatters, and adversarial security properties.

```bash
# Run complete test suite with coverage gate (>= 90%)
pytest

# Strict type checking (100% type hint enforcement)
mypy --strict src tests

# Static linting and code formatting
ruff check .
ruff format --check .

# Security SAST audit
bandit -r src/
```

---

## Security & Threat Model (STRIDE)

| Threat (STRIDE) | Attack Vector | Security Control | Residual Risk |
| :--- | :--- | :--- | :--- |
| **Spoofing** | Attacker injects rogue machine into subnet | Subnet router enforces strict IP/MAC binding and CIDR validation. | Low |
| **Tampering** | Mutation of telemetry logs or scores | SQLite WAL persistence is append-only; in-memory queues are frozen upon collection. | Low |
| **Repudiation** | Operator denies modifying firewall rules or running scenarios | Audit log records every operational action with timestamp and details. | Low |
| **Information Disclosure** | Exposure of internal lab tokens outside range | All credentials are synthetic test artifacts; sensitive tokens redacted in API responses. | Very Low |
| **Denial of Service** | Infinite attack loops in scenario DAGs | Graph step bounds ($N \le 100$) and execution timeouts enforced. | Low |
| **Elevation of Privilege** | Unauthenticated API compromise | Pydantic strict validation (`extra="forbid"`) prevents parameter injection. | Low |

---

## Docker Deployment

Build and run using rootless Docker Compose:
```bash
# Build and run container
docker compose up -d

# Check health status
docker compose ps

# View logs
docker compose logs -f
```

---

## Responsible Use Charter

This software is strictly intended for **educational, defensive, and authorized cyber range evaluation**. All offensive emulation techniques execute harmless synthetic payloads in local virtual models. Do not use this software against systems you do not own or lack explicit written authorization to test.

---

## License

Released under the [MIT License](LICENSE). Copyright © 2026 Cybersecurity Engineering Team.
