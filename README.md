# Security prototype

A self-contained lab that hardens production database access for a containerized app. The app is an Angular frontend with a .NET 10 / PostgreSQL 17 backend and a Laravel 13 / MariaDB 11.8 backend. Everything is free and self-hosted. Developers get database access that is **temporary, read-only by default, per person, masked, and audited**, and most debugging happens from telemetry instead.

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\gen-secrets.ps1
docker compose up -d --build
powershell -ExecutionPolicy Bypass -File .\scripts\setup.ps1
powershell -ExecutionPolicy Bypass -File .\tests\run-all.ps1
```

- **[docs/PLAYBOOK.md](docs/PLAYBOOK.md)**: how to run, use, configure and troubleshoot the stack.
- **[docs/DECISIONS.md](docs/DECISIONS.md)**: the key decisions and the reasoning behind them (D1 to D13).

## What is in the stack

| Area | Components |
|---|---|
| Application | `web` (nginx + Angular), `dotnet-api`, `laravel-api`, one-shot `*-migrate` jobs |
| Databases | `pg-primary` and `pg-replica` (pgAudit), `maria-primary` and `maria-replica` (`server_audit`), all over TLS with a lab CA |
| Just-in-time access | Keycloak (identity), OpenBao (short-lived database users), the approval `portal` |
| Revocation | `pg-sweeper`, `maria-sweeper`, `lease-reconciler`, the replica startup purge and expiry event, the PostgreSQL replica deny list |
| Audit | `fluent-bit` ships every audit log, read-only, into `log-store` (`audit.jsonl`, `alerts.jsonl`) |
| Debug telemetry | `alloy` (redaction) → `loki`, `tempo` → `grafana` (Keycloak sign-in) |

## Layout

```
compose.yaml        the whole stack (address plan and reasoning in the comments)
apps/               dotnet-api, laravel-api, web (Angular), portal (ASP.NET Core + Angular)
config/             database init and setup scripts, OpenBao, Keycloak realm, Fluent Bit, telemetry
images/             postgres:17 + pgAudit + tini
scripts/            gen-secrets, setup (5 stages), unseal, stale-users
tests/              smoke and 8 check suites, run-all
docs/               PLAYBOOK.md, DECISIONS.md
secrets/            generated, git-ignored
```

Lab only: OpenBao's unseal key and root token are plain files, Keycloak runs in dev mode over HTTP, and the test users' passwords are in the repository. See "Lab-only shortcuts" in [DECISIONS.md](docs/DECISIONS.md).
