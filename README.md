# AegisAI

[![License: BUSL-1.1](https://img.shields.io/badge/License-BUSL%201.1-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11%2B-blue)](https://www.python.org/)
[![CI](https://github.com/Bobcatsfan33/AegisAI/actions/workflows/ci.yml/badge.svg)](https://github.com/Bobcatsfan33/AegisAI/actions/workflows/ci.yml)
[![Security: FedRAMP-aligned](https://img.shields.io/badge/Security-FedRAMP%20High%20%7C%20IL6%20aligned-red)](SECURITY.md)
[![PRs: owner approval required](https://img.shields.io/badge/PRs-owner%20approval%20required-yellow)](CONTRIBUTING.md)

> **v4.0** — ClickHouse analytics, materialized views, cross-product analytics, custom dashboard. Full Elasticsearch/OpenSearch replacement.

**Autonomous multi-cloud and network security posture management with AI-driven security analysis.**

AegisAI scans your AWS, Azure, GCP, and network infrastructure for vulnerabilities, then deploys AI-driven agents to remediate them autonomously. It includes AI-specific security tooling: automated red teaming, runtime guardrails, policy enforcement, asset discovery, and ClickHouse-backed telemetry.

---

## Architecture

```
aegis/
├── api.py                        # FastAPI REST API (RBAC + audit log)
├── main.py                       # CLI entry point
├── auth.py                       # OIDC / JWT verification
├── config.py                     # All config from environment variables
├── modules/
│   ├── agents/                   # AegisAI — AI remediation agents
│   │   ├── orchestrator.py       #   AI agentic loop (function-calling)
│   │   ├── cloud_agent.py        #   AWS / Azure / GCP remediations
│   │   ├── network_agent.py      #   iptables, pkill, port blocking
│   │   └── siem_agent.py         #   Syslog RFC 5424, CEF, webhook
│   ├── scanners/                 # AegisAI — infrastructure scanners
│   │   ├── aws/                  #   S3, Security Groups, IAM, CloudTrail, RDS
│   │   ├── azure/                #   Azure resource scanning
│   │   ├── gcp/                  #   GCP resource scanning
│   │   ├── network/              #   nmap + raw socket + flow monitoring
│   │   ├── acas/                 #   ACAS/Nessus vulnerability scanning
│   │   ├── host/                 #   YARA engine + download scanner
│   │   ├── iac/                  #   Terraform/CloudFormation shift-left
│   │   └── k8s/                  #   Kubernetes CIS Benchmark
│   ├── compliance/               # AegisAI — compliance frameworks
│   │   ├── stig.py               #   DISA STIG automated assessment
│   │   ├── ssp_generator.py      #   eMASS SSP auto-generator
│   │   └── conmon.py             #   Continuous monitoring
│   ├── security/                 # Shared — security infrastructure
│   │   ├── audit_log.py          #   Immutable hash-chained audit log
│   │   ├── rbac.py               #   Role-based access control
│   │   ├── encryption.py         #   AES-256-GCM field-level encryption
│   │   ├── fips.py               #   FIPS 140-2 enforcement
│   │   ├── headers.py            #   Security headers middleware
│   │   └── secrets.py            #   Secrets manager backend
│   ├── analytics/                # Shared — ClickHouse analytics
│   │   ├── clickhouse_indexer.py #   Drop-in ClickHouse indexer
│   │   ├── cross_product.py      #   Cross-product analytics (Aegis + TokenDNA)
│   │   └── dashboard.html        #   Custom analytics dashboard
│   ├── transport/                # Shared — mTLS service mesh
│   ├── tenants/                  # Shared — multi-tenancy
│   ├── identity/                 # Shared — Redis identity cache
│   ├── reports/                  # Shared — compliance report generation
│   │
│   └── aegis_ai/                 # ◀ AegisAI — AI Security subcomponent
│       ├── routes.py             #   /api/ai/* endpoints
│       ├── connectors/           #   Multi-provider LLM abstraction
│       │   ├── openai_connector  #     OpenAI / Ollama / vLLM / LM Studio
│       │   └── anthropic_connector#    Anthropic Claude
│       ├── discovery/            #   AI asset inventory
│       ├── redteam/              #   Automated adversarial testing (20+ attacks)
│       ├── guardrails/           #   Runtime LLM I/O enforcement
│       ├── policy/               #   AI governance (NIST AI RMF, EU AI Act)
│       └── telemetry/            #   ClickHouse event analytics + materialized views
│
├── tests/                        # pytest suite
├── Dockerfile                    # CIS Benchmark hardened
├── docker-compose.yml            # Full stack (app + ClickHouse + Redis)
├── Vagrantfile                   # Isolated VM for remediation testing
└── requirements.txt
```

---

## Quick start

### 1. Configure

```bash
cp .env.example .env
# Edit .env — at minimum set OPENAI_API_KEY (or OPENAI_BASE_URL for local LLMs)
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3a. Run — CLI

```bash
python main.py                          # scan all enabled providers (dry run)
python main.py --providers aws,network  # scan specific providers
python main.py --live                   # live remediation (requires AUTO_REMEDIATE=true)
```

### 3b. Run — REST API

```bash
uvicorn api:app --host 0.0.0.0 --port 8000 --reload
```

### 3c. Run — Full stack (Docker Compose)

```bash
docker compose up -d
```

Spins up: **AegisAI API** on `:8000` · **ClickHouse** on `:9000` · **Redis** on `:6379`

---

## API Endpoints

### AegisAI (Infrastructure)

| Endpoint | Auth | Description |
|---|---|---|
| `GET /` | None | Health check |
| `POST /scan` | ANALYST+ | Start async scan + remediation |
| `GET /scan/{scan_id}` | ANALYST+ | Poll scan status / results |
| `GET /api/findings` | ANALYST+ | Paginated findings query |
| `GET /api/compliance` | ANALYST+ | NIST 800-53 compliance gap report |
| `GET /api/stig` | ANALYST+ | DISA STIG assessment |
| `GET /api/acas` | ANALYST+ | ACAS/Nessus vulnerability summary |
| `GET /api/ssp` | ANALYST+ | eMASS SSP auto-generated payload |
| `GET /api/audit` | OWNER | Immutable audit log |

### AegisAI (AI Security)

| Endpoint | Auth | Description |
|---|---|---|
| `POST /api/ai/discover` | ANALYST+ | AI asset discovery scan |
| `POST /api/ai/redteam` | ADMIN+ | Automated red team attacks |
| `POST /api/ai/guardrails` | ANALYST+ | Evaluate content against guardrails |
| `POST /api/ai/policy/evaluate` | ANALYST+ | Policy engine evaluation |
| `GET /api/ai/telemetry/stats` | ADMIN+ | Telemetry engine status |
| `GET /api/ai/connectors` | ANALYST+ | List registered LLM connectors |
| `GET /api/ai/dashboard` | ANALYST+ | Unified AegisAI dashboard |

---

## Security & Compliance

AegisAI is built toward **FedRAMP High** and **DoD IL6** alignment.

| Control Family | Implementation |
|---|---|
| **AU-2 / AU-3 / AU-9** | Immutable hash-chained JSONL audit log; HMAC-SHA256 tamper detection |
| **AC-3 / AC-6** | 4-tier RBAC (OWNER / ADMIN / ANALYST / READONLY) |
| **SC-8 / SC-8(1)** | mTLS service mesh (proxy + native mode); FIPS cipher suites |
| **SC-28 / SC-28(1)** | AES-256-GCM field-level envelope encryption |
| **IA-3 / IA-5** | OIDC/JWT auth; AWS Secrets Manager / HashiCorp Vault backend |
| **CM-7** | CIS Docker hardening; seccomp syscall allowlist; non-root container |
| **SI-2** | CI: CodeQL, pip-audit, TruffleHog, Trivy, Ruff on every PR |

---

## Contributing

All community contributions are welcome. Every PR must be approved by the repository owner before merge. Read [CONTRIBUTING.md](CONTRIBUTING.md) for the security checklist and disclosure process.

---

## License

Business Source License 1.1 (BUSL-1.1). See [LICENSE](LICENSE).
Free for non-competing use; converts to Apache 2.0 four years from first public release.
