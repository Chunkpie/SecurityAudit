# SecAudit — Website Deployment Readiness & Security Audit Platform

A production-ready platform that determines whether a website is secure enough to deploy or
continue operating in production. Scans run **without requiring any paid AI APIs** — the entire
scanning, scoring, and reporting pipeline operates on $0/scan using open-source security tools.

> **Verdict system:** Every scan produces a clear **GO** / **GO WITH CONDITIONS** / **NO-GO**
> deployment recommendation backed by a 0–100 security score and detailed, evidence-backed findings.

---

## ✨ Features

- 🔍 **Multi-tool scan orchestration** — Nmap, Nuclei, SQLMap, FFUF/Gobuster, SSLyze/testssl.sh, and custom checks
- 🛡️ **10+ audit categories** — TLS/HTTPS, auth, sensitive data exposure, injection, XSS, access control, CSRF, clickjacking, server hardening, cloud security
- 📊 **Weighted risk scoring** with deterministic GO/GO-WITH-CONDITIONS/NO-GO verdicts
- 📄 **Downloadable reports** — PDF (via Playwright), JSON, and CSV with full evidence and remediation guidance
- 🏢 **Multi-tenant** organizations with role-based access control (Owner/Admin/Member/Viewer)
- ⚡ **Async scan orchestration** via Celery + Redis with live status polling
- 🔄 **CI/CD security gates** — GitHub Actions, GitLab CI, and Jenkins templates that block deployments on failing audits
- 📈 **Prometheus + Grafana** monitoring out of the box
- 🔐 **JWT auth** with refresh tokens, audit logging, and consent tracking on every scan
- 🤖 **Optional local AI** (Ollama) — never required, the platform is 100% functional without it

---

## 🏗️ Architecture

```
┌─────────────┐      ┌──────────────┐      ┌─────────────────┐
│   Next.js   │─────▶│   FastAPI    │─────▶│   PostgreSQL     │
│  Frontend   │◀─────│   Backend    │◀─────│   (scans, etc.)  │
└─────────────┘      └──────┬───────┘      └─────────────────┘
                             │
                             ▼
                      ┌──────────────┐      ┌─────────────────┐
                      │ Celery Queue │─────▶│      Redis       │
                      │   (Scans)    │◀─────│  (broker/cache)  │
                      └──────┬───────┘      └─────────────────┘
                             │
                             ▼
              ┌──────────────────────────────┐
              │      Celery Worker Pool       │
              │  Nmap · Nuclei · SQLMap · ... │
              └──────────────────────────────┘
```

All services run behind an **Nginx** reverse proxy with rate limiting and security headers.
**Prometheus** scrapes metrics; **Grafana** visualizes them.

---

## 📦 Tech Stack

| Layer | Technology |
|---|---|
| Frontend | Next.js 15, TypeScript, Tailwind CSS, TanStack Query, Recharts, Zustand |
| Backend | FastAPI, Python 3.12, SQLAlchemy 2.0 (async), Pydantic v2 |
| Database | PostgreSQL 16 |
| Queue | Redis + Celery (workers + beat scheduler) |
| Auth | JWT (access + refresh tokens), bcrypt password hashing |
| Reports | Playwright (HTML→PDF), native JSON/CSV |
| Scanning | Nmap, Nuclei, SQLMap, FFUF, Gobuster, SSLyze, testssl.sh |
| Infra | Docker Compose, Nginx, Prometheus, Grafana |

---

## 🚀 Quick Start (Docker Compose)

### Prerequisites
- Docker & Docker Compose v2
- 4GB+ RAM recommended (scanning tools are resource-intensive)

### 1. Clone and configure

```bash
cd secaudit
cp .env.example .env
```

Edit `.env` and set strong values for `POSTGRES_PASSWORD`, `REDIS_PASSWORD`, `SECRET_KEY`, and
`JWT_SECRET_KEY`. Generate secure secrets with:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(64))"
```

### 2. Build and start all services

```bash
docker compose up -d --build
```

This starts: `postgres`, `redis`, `api`, `worker`, `beat`, `frontend`, `nginx`, `prometheus`, `grafana`.

### 3. Run database migrations

```bash
docker compose exec api alembic upgrade head
```

### 4. Access the platform

| Service | URL |
|---|---|
| Web App | http://localhost (via Nginx) or http://localhost:3000 directly |
| API Docs | http://localhost:8000/api/docs |
| Grafana | http://localhost:3001 (admin / value of `GRAFANA_PASSWORD`) |
| Prometheus | http://localhost:9090 |

Register an account, create an organization, and launch your first scan.

---

## 🛠️ Development Setup (without Docker)

### Backend

```bash
cd backend
python3.12 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Install scanning tools locally (Ubuntu/Debian example)
sudo apt-get install nmap sqlmap gobuster
# Nuclei: https://github.com/projectdiscovery/nuclei#install
# FFUF: https://github.com/ffuf/ffuf#installation
pip install sslyze
playwright install chromium

cp .env.example .env   # configure POSTGRES_*, REDIS_* for local services
alembic upgrade head
uvicorn app.main:app --reload --port 8000
```

In a separate terminal, start the Celery worker:

```bash
celery -A app.workers.tasks.celery_app worker --loglevel=info -Q scans,reports
```

And the beat scheduler (for scheduled scans):

```bash
celery -A app.workers.tasks.celery_app beat --loglevel=info
```

### Frontend

```bash
cd frontend
npm install --legacy-peer-deps
cp .env.example .env.local   # set NEXT_PUBLIC_API_URL=http://localhost:8000
npm run dev
```

Visit http://localhost:3000.

---

## 🏭 Production Deployment

1. **Provision a VPS** (see sizing recommendations below).
2. **Set up DNS** pointing to your server.
3. **Obtain TLS certificates** (Let's Encrypt via certbot) and mount them into
   `infrastructure/nginx/conf.d` — uncomment the HTTPS server block in `default.conf`.
4. **Set strong secrets** in `.env` — never reuse the example values.
5. **Run with restart policies**: `docker compose up -d` (all services use `restart: unless-stopped`).
6. **Set up automated backups** for the `postgres_data` volume.
7. **Configure firewall** to only expose ports 80/443 publicly; keep 5432, 6379, 9090 internal.
8. **Enable scheduled scan cleanup** — old reports can be pruned via a cron job against `/app/reports`.

### Recommended VPS sizing

| Tier | Specs | Concurrent Scans |
|---|---|---|
| Starter | 2 vCPU / 4GB RAM | 1–2 |
| Standard | 4 vCPU / 8GB RAM | 3–5 |
| Scale | 8 vCPU / 16GB RAM + dedicated worker nodes | 10+ |

Scanning tools (Nmap, SQLMap, Nuclei) are CPU and network-bound; scale worker replicas
horizontally (`docker compose up -d --scale worker=3`) for higher throughput.

---

## 🔌 CI/CD Integration

Block deployments automatically when a scan returns `NO_GO`. Templates are provided in:

- `.github/workflows/security-gate-template.yml` (GitHub Actions)
- `scripts/gitlab-ci-template.yml` (GitLab CI)
- `scripts/Jenkinsfile.template` (Jenkins)

Copy the relevant template into your **own project's** CI configuration, set the required
secrets (`SECAUDIT_API_URL`, `SECAUDIT_API_KEY`, `SECAUDIT_ORG_ID`, `STAGING_URL`), and deployments
will be gated on the `/api/v1/cicd/gate/{scan_id}` endpoint, which returns:

```json
{
  "status": "NO_GO",
  "security_score": 62,
  "critical_findings": 3,
  "high_findings": 7,
  "passed": false
}
```

---

## 🤖 Optional Local AI (Ollama)

The platform never requires AI to function. If you want AI-assisted remediation summaries,
set in `.env`:

```
OLLAMA_ENABLED=true
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=llama3
```

This is purely additive — all scanning, scoring, and reporting work identically with or without it.

---

## 🗺️ Roadmap

**Phase 1 (MVP — included in this repo)**
Core scanning engine, auth, multi-tenant orgs, PDF/JSON/CSV reports, dashboard UI, CI/CD gates.

**Phase 2 (Public Beta)**
Subdomain auto-discovery (Subfinder/Amass), source code scanning (Semgrep/Trivy/Gitleaks),
scheduled scan comparison reports, webhook notifications, screenshot evidence capture.

**Phase 3 (Commercial)**
Team billing/subscriptions, white-label reports, SSO/SAML, compliance mapping (PCI-DSS/SOC2),
dedicated scan infrastructure per tenant.

---

## ⚖️ Legal

See [`TERMS_OF_SERVICE.md`](./TERMS_OF_SERVICE.md). **Users must only scan assets they own or
are explicitly authorized to test.** Every scan records consent, timestamp, and IP address to
the audit trail.

---

## 📁 Repository Structure

```
secaudit/
├── backend/                  # FastAPI application
│   ├── app/
│   │   ├── api/v1/endpoints/ # REST API route handlers
│   │   ├── core/             # Config, security, database, redis
│   │   ├── models/           # SQLAlchemy ORM models
│   │   ├── schemas/          # Pydantic request/response schemas
│   │   ├── services/         # Report generation, business logic
│   │   └── workers/
│   │       ├── scanners/     # Individual scanner modules (TLS, headers, nmap, etc.)
│   │       ├── orchestrator.py  # Coordinates all scanners, computes score/verdict
│   │       └── tasks.py      # Celery task definitions
│   ├── migrations/           # Alembic database migrations
│   ├── tests/                # Pytest test suite
│   ├── Dockerfile            # API server image
│   └── Dockerfile.worker     # Worker image (includes all scanning tools)
├── frontend/                  # Next.js application
│   └── src/
│       ├── app/               # App Router pages (dashboard, auth, scans, findings...)
│       ├── lib/                # API client, utils, Zustand store
│       └── types/              # Shared TypeScript types
├── infrastructure/
│   ├── nginx/                 # Reverse proxy config
│   └── monitoring/            # Prometheus + Grafana provisioning
├── .github/workflows/         # CI pipelines + reusable security gate template
├── scripts/                   # GitLab CI / Jenkins templates, DB init
├── docker-compose.yml
└── TERMS_OF_SERVICE.md
```
