# SecAudit

A self-hosted platform that answers one question before you ship: **is this thing actually safe to put in production, or are we about to find out the hard way?**

You point it at a target, it runs a real scanning pipeline (Nmap, Nuclei, SQLMap, FFUF/Gobuster, SSLyze/testssl.sh, plus a bunch of custom checks), scores the result 0–100, and spits out a deployment verdict: **GO**, **GO WITH CONDITIONS**, or **NO-GO**. No paid AI API calls anywhere in the pipeline. $0/scan, every time, using open-source tooling you'd otherwise be running by hand in five different terminal tabs.

I built this because I got tired of doing the same manual recon → scan → triage → write-up loop for every app/site I was asked to look at, and wanted something that gates CI/CD the way a senior pentester gates a release — refuses to sign off until the findings say it's fine.

---

## What it actually does

- Orchestrates a real multi-tool scan: TLS/cert hygiene, auth weaknesses, sensitive data exposure, injection (SQLi via SQLMap), XSS, broken access control, CSRF, clickjacking, server/header hardening, basic cloud misconfig checks
- Turns raw tool output into a weighted risk score instead of a wall of unreadable logs
- Produces a deterministic verdict — same findings always produce the same verdict, no vibes-based scoring
- Generates PDF/JSON/CSV reports with evidence and remediation steps you can actually hand to a dev team
- Gates deployments in GitHub Actions / GitLab CI / Jenkins — fail the audit, fail the pipeline
- Multi-tenant with proper RBAC (Owner/Admin/Member/Viewer), JWT auth, audit logging, consent tracking on every single scan
- Async scan execution via Celery + Redis so you're not blocking on a 10-minute Nmap run
- Prometheus + Grafana wired in out of the box because if you can't see it, you can't trust it
- Optional local AI via Ollama for remediation summaries — fully optional, the core platform doesn't need it and never will

---

## Stack

| Layer | Tech |
|---|---|
| Frontend | Next.js 15, TypeScript, Tailwind, TanStack Query, Recharts, Zustand |
| Backend | FastAPI, Python 3.12, SQLAlchemy 2.0 (async), Pydantic v2 |
| DB | PostgreSQL 16 |
| Queue | Redis + Celery (worker + beat) |
| Auth | JWT (access + refresh), bcrypt |
| Reports | Playwright (HTML→PDF), native JSON/CSV |
| Scanners | Nmap, Nuclei, SQLMap, FFUF, Gobuster, SSLyze, testssl.sh |
| Infra | Docker Compose, Nginx, Prometheus, Grafana |

```
Next.js  ⇄  FastAPI  ⇄  PostgreSQL
              │
              ▼
        Celery + Redis
              │
              ▼
     Worker pool (Nmap · Nuclei · SQLMap · FFUF/Gobuster · SSLyze...)
```

Everything sits behind Nginx with rate limiting and security headers turned on by default, because a security tool with sloppy headers on its own frontend is a special kind of embarrassing.

---

## Before you touch anything: the rule

**Only scan things you own or have explicit written authorization to test.** Every scan logs consent, a timestamp, and the requesting IP into the audit trail — this isn't decorative, it's there because active scanning (SQLMap, Nuclei, Gobuster) against a target you don't control is a good way to get a very unpleasant phone call, or worse, a CFAA-flavored one. Read `TERMS_OF_SERVICE.md`. Don't be the reason this project gets a bad name.

---

## Getting it running (Docker — do this one)

You need Docker + Docker Compose v2, and ideally 4GB+ RAM since the scanner stack is not lightweight.

```bash
cd secaudit
cp .env.example .env
```

Open `.env` and actually change `POSTGRES_PASSWORD`, `REDIS_PASSWORD`, `SECRET_KEY`, and `JWT_SECRET_KEY`. Do not ship the example values, I will know.

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(64))"
```
Run that four times, paste the outputs in. Takes ten seconds, saves you from being the example in someone's "how not to deploy" blog post.

Bring everything up:

```bash
docker compose up -d --build
```

That spins up `postgres`, `redis`, `api`, `worker`, `beat`, `frontend`, `nginx`, `prometheus`, `grafana` — all of it, restart policies included.

Migrate the DB:

```bash
docker compose exec api alembic upgrade head
```

Then go in:

| Service | Where |
|---|---|
| App | `http://localhost` (Nginx) or `http://localhost:3000` direct |
| API docs | `http://localhost:8000/api/docs` |
| Grafana | `http://localhost:3001` — login `admin` / your `GRAFANA_PASSWORD` |
| Prometheus | `http://localhost:9090` |

Register, spin up an org, launch your first scan against something you're allowed to hit.

---

## Running it bare-metal (no Docker)

If you want to actually understand what's happening under the hood, or you're on a box where Docker isn't an option, here's the manual path.

**Backend:**

```bash
cd backend
python3.12 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Get the scanning tools installed locally:

```bash
sudo apt-get install nmap sqlmap gobuster
pip install sslyze
playwright install chromium
```

Nuclei and FFUF aren't in apt by default — grab them from their respective repos:
- Nuclei: https://github.com/projectdiscovery/nuclei#install
- FFUF: https://github.com/ffuf/ffuf#installation

Then:

```bash
cp .env.example .env   # point at your local Postgres/Redis
alembic upgrade head
uvicorn app.main:app --reload --port 8000
```

Separate terminal — the worker (this is where the actual scanning happens, don't forget it or your scans will queue forever and you'll be debugging the wrong thing for 20 minutes like I did):

```bash
celery -A app.workers.tasks.celery_app worker --loglevel=info -Q scans,reports
```

And if you want scheduled/recurring scans, the beat scheduler too:

```bash
celery -A app.workers.tasks.celery_app beat --loglevel=info
```

**Frontend:**

```bash
cd frontend
npm install --legacy-peer-deps
cp .env.example .env.local   # NEXT_PUBLIC_API_URL=http://localhost:8000
npm run dev
```

`http://localhost:3000`. Done.

---

## Wiring it into CI/CD

The actual point of this tool, IMO — let the pipeline kill the deploy if the audit comes back bad, instead of someone eyeballing a PDF at 5pm on a Friday and shipping anyway.

Templates live in:
- `.github/workflows/security-gate-template.yml`
- `scripts/gitlab-ci-template.yml`
- `scripts/Jenkinsfile.template`

Drop the relevant one into your own repo's CI config, set `SECAUDIT_API_URL`, `SECAUDIT_API_KEY`, `SECAUDIT_ORG_ID`, `STAGING_URL` as secrets, and your pipeline now hits `/api/v1/cicd/gate/{scan_id}`, which returns exactly what you need to fail the build:

```json
{
  "status": "NO_GO",
  "security_score": 62,
  "critical_findings": 3,
  "high_findings": 7,
  "passed": false
}
```

`passed: false` → fail the job. That's it. No interpretation needed, which is the whole point of a deterministic scorer.

---

## Local AI (optional, genuinely optional)

If you want plain-English remediation summaries on top of the raw findings, point it at a local Ollama instance:

```
OLLAMA_ENABLED=true
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=llama3
```

Turn this off and nothing breaks. Scoring, scanning, and reporting don't depend on it — it's a nice-to-have layer for summarizing what the scanners already found, not a dependency.

---

## Repo layout

```
secaudit/
├── backend/
│   ├── app/
│   │   ├── api/v1/endpoints/   # route handlers
│   │   ├── core/               # config, security, db, redis
│   │   ├── models/             # SQLAlchemy ORM
│   │   ├── schemas/            # Pydantic schemas
│   │   ├── services/           # report gen + business logic
│   │   └── workers/
│   │       ├── scanners/       # one module per scanner (tls, headers, nmap...)
│   │       ├── orchestrator.py # runs scanners, computes score + verdict
│   │       └── tasks.py        # Celery task defs
│   ├── migrations/             # Alembic
│   ├── tests/
│   ├── Dockerfile
│   └── Dockerfile.worker       # bundles all scanning tools
├── frontend/
│   └── src/
│       ├── app/                # App Router pages
│       ├── lib/                # API client, utils, Zustand store
│       └── types/
├── infrastructure/
│   ├── nginx/
│   └── monitoring/             # Prometheus + Grafana provisioning
├── .github/workflows/
├── scripts/                    # GitLab/Jenkins templates, DB init
├── docker-compose.yml
└── TERMS_OF_SERVICE.md
```


## A few notes from actually running this

- The worker image is heavier than the API image because it bundles every scanning tool — don't be surprised by the build time on first `docker compose up --build`.
- If a scan looks stuck, check the worker logs before anything else (`docker compose logs -f worker`). 90% of the time it's a queue not being consumed, not an actual scan hang.
- SQLMap and Nuclei runs can be loud on the target's logs — if you're testing your own staging environment, expect your WAF/IDS to light up. That's expected, not a bug.
- The verdict thresholds are intentionally conservative. If you think NO-GO is being too aggressive for your risk appetite, that's a config change in the orchestrator, not a reason to ignore the gate.

---

## Contributing

PRs welcome, especially on the scanner modules and verdict scoring logic — that's the part most likely to have edge cases I haven't hit yet.

Before opening a PR:

1. Fork it, branch off `main` with something descriptive (`fix/sqlmap-timeout-handling`, not `patch-1`).
2. If you're touching `orchestrator.py` or anything in `workers/scanners/`, add/update tests in `backend/tests/` — scoring logic without tests is just vibes, and we said no to vibes-based scoring up top.
3. Run the existing suite before you push:
   ```bash
   cd backend
   pytest
   ```
4. Keep PRs scoped to one thing. A new scanner module and a frontend refactor in the same PR is a pain for both of us to review.
5. If you're adding a new scanner integration, follow the existing pattern in `workers/scanners/` — same input/output shape so the orchestrator doesn't need special-casing.

**Good first issues:** new check categories under `workers/scanners/`, additional CI templates (Circle CI, Drone, etc.), report formatting improvements, Grafana dashboard tweaks.

**Things to talk through in an issue first before sending a PR:** anything touching auth/JWT logic, the consent/audit-logging flow, or the verdict scoring weights — these are the parts where a "small" change can quietly turn a NO-GO into a GO and nobody notices until it matters.

Found a bug instead of a feature? Open an issue with the target type (don't paste real scan output from someone else's site), steps to reproduce, and what you expected vs. what happened.

---

## License & legal

See `TERMS_OF_SERVICE.md`. Scan responsibly — authorization isn't optional, it's the entire legal basis for this tool existing.

---

⭐ if this saved you from a bad deploy. Built by **Feizan**.