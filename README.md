# NetSentinel

NetSentinel is a modular secure-access management platform. This repository contains the Phase 1 production foundation: a FastAPI management API, PostgreSQL schema and migrations, Redis-backed policy cache/readiness checks, a React/TypeScript portal, an asynchronous worker boundary, and Docker deployment.

## Quick start

1. Copy `.env.example` to `.env` and replace every `CHANGE_ME` value.
2. Run `docker compose up --build`.
3. Open `http://localhost:8080`. API documentation is at `http://localhost:8000/docs` in development.
4. Bootstrap the first administrator once:

   `docker compose exec api python -m app.cli create-admin admin@example.com`

The bootstrap command prompts for a password and refuses to run when an administrator already exists.

## Repository layout

- `backend/` — management API, domain services, migrations, tests
- `frontend/` — React admin portal
- `deploy/` — reverse proxy configuration
- `docs/` — architecture, security, data, deployment, agent, and delivery plans

## Development

Backend tests: `cd backend && pip install -e .[dev] && pytest`

Frontend checks: `cd frontend && npm ci && npm run typecheck && npm run build`

See [architecture](docs/architecture.md), [security](docs/security.md), and [operations](docs/operations.md) before deployment.
