# Playbook: run and configure the stack

The commands below are for Windows PowerShell 5.1 or later. Run them from the repository root. For *why* things are built this way, see [DECISIONS.md](DECISIONS.md).

## 1. Prerequisites

- **Docker Desktop** with the WSL2 backend, and **git**. Nothing else goes on the host: the `bao`, `psql` and `mariadb` clients run in throwaway containers.
- **About 2 GiB of RAM for the stack.** On an 8 GB machine, cap WSL2 at about 5 GB in `%UserProfile%\.wslconfig`, then run `wsl --shutdown` and restart Docker Desktop:

  ```ini
  [wsl2]
  memory=5GB
  ```

- **Free host ports:** 8080 (app, all interfaces), and 8090, 3000, 8180 and 8200 (loopback only).
- **Line endings:** keep the repository's `.gitattributes`. Init scripts with CRLF line endings fail silently inside the containers.

## 2. First start (about 10 minutes)

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\gen-secrets.ps1
docker compose up -d --build
powershell -ExecutionPolicy Bypass -File .\scripts\setup.ps1
```

| Step | What it does |
|---|---|
| `gen-secrets.ps1` | Writes random passwords, client secrets and placeholders into `secrets\` (git-ignored). It keeps files that already exist. |
| `docker compose up -d --build` | Builds the app images and starts the stack. `pki-init`, `log-init`, `telemetry-init`, `portal-init`, `dotnet-migrate` and `laravel-migrate` are one-shot jobs: **exit code 0 is expected**. The replicas take a minute or two to clone and seed. |
| `setup.ps1` | Configures everything, in five idempotent stages (below). It ends by printing the URLs. |

`setup.ps1` runs these stages in order. Each stage can be re-run on its own once the stages before it have run.

| Stage | Script | Configures |
|---|---|---|
| 1 | `setup-access.ps1` | Masked views, `debug_ro`, `bao_admin`. Initialises and unseals OpenBao. Sets up the database secrets engine and OIDC/JWT auth against Keycloak. |
| 2 | `setup-replicas.ps1` | Sweeper accounts. Waits until both replicas have caught up. |
| 3 | `setup-audit.ps1` | MariaDB temp users on the replica, pgAudit role settings, revocation backstops, lease reconciler. Checks that audit shipping works. |
| 4 | `setup-telemetry.ps1` | Waits for Loki, Tempo, Alloy and Grafana. |
| 5 | `setup-portal.ps1` | Portal clients, groups and permissions in Keycloak; approvers `carol` and `dave`; the PostgreSQL write path. |

## 3. Check that it works

```powershell
# quick: the app works through nginx, and no database port is open (under a minute)
powershell -ExecutionPolicy Bypass -File .\tests\smoke.ps1

# everything (about 30 minutes). Run suites one at a time, never in parallel.
powershell -ExecutionPolicy Bypass -File .\tests\run-all.ps1
# or a selection
powershell -ExecutionPolicy Bypass -File .\tests\run-all.ps1 -Suite portal,write-access
```

| Suite | File | Covers | Time |
|---|---|---|---|
| `smoke` | `smoke.ps1` | App through nginx; database ports closed | < 1 min |
| `hardening` | `hardening-checks.ps1` | Network isolation, DB privileges, TLS, superuser lockdown, secrets (D2, D3) | 1-2 min |
| `jit-access` | `jit-access-checks.ps1` | OpenBao login as `alice` / `bob`, temp users, masking, revoke, expiry. Restarts OpenBao once. (D4, D5) | ~3 min |
| `replica` | `replica-checks.ps1` | Replicas, `pg_hba` split, sweepers, revoke while a replica is down (D5, D7) | ~4 min |
| `audit` | `audit-checks.ps1` | Audit records and alerts in the store, password-leak scans (D6, D9) | ~5 min |
| `revocation` | `revocation-checks.ps1` | Startup purge, expiry event, reconciler, PostgreSQL deny list during outages (D8) | ~10 min |
| `telemetry` | `telemetry-checks.ps1` | Traces, logs, redaction, isolation, Grafana sign-in (D10) | ~2 min |
| `portal` | `portal-checks.ps1` | Approval rules, expiry, drift, service-account limits (D11) | ~3 min |
| `write-access` | `write-access-checks.ps1` | Write path and its three audit layers (D12) | ~2 min |

Each check prints `PASS`/`FAIL`. A negative check passes only if the error text matches the control under test, and the real error text is printed below it.

Optional long tests:
- `tests\revocation-checks.ps1 -IrrevocableTest` adds about 13 minutes and produces a real irrevocable lease.
- `tests\audit-checks.ps1 -LeakAndPurgeTest` reproduces the MariaDB binlog leak and purges it. **It deletes all older binlogs.**

## 4. Endpoints and lab accounts

| What | URL | Sign in |
|---|---|---|
| App | http://localhost:8080 | none |
| Approval portal | http://localhost:8090 | Keycloak |
| Grafana (traces, logs) | http://localhost:3000 | Keycloak, `app1-devs` members only |
| OpenBao UI | https://localhost:8200/ui | OIDC (accept the lab CA certificate warning) |
| Keycloak admin | http://keycloak.localhost:8180/admin | `admin` / `secrets\keycloak_admin_password` |

| User | Role | Password |
|---|---|---|
| `alice` | Developer, standing member of `app1-devs` (the tests rely on her) | `config\keycloak\lab-realm.json` |
| `bob` | Developer without access, who requests it through the portal | `config\keycloak\lab-realm.json` |
| `carol` | Read-access approver (`app1-approvers`) | `secrets\keycloak_carol_password` |
| `dave` | Write-access approver (`app1-write-approvers`) | `secrets\keycloak_dave_password` |

All of these are LAB-ONLY. `*.localhost` resolves to 127.0.0.1 in current browsers without a hosts-file entry.

## 5. Day-to-day operations

| Situation | Do this |
|---|---|
| Stop and keep the data | `docker compose stop` |
| Start again, or after a reboot or Docker Desktop restart | `docker compose up -d`, then `scripts\unseal.ps1` (OpenBao always starts **sealed**). `setup.ps1` works too. |
| Changed a file under `config\` | `docker compose up -d --force-recreate <service>`. Compose does not notice changes to mounted config files. If it was `openbao`, run `unseal.ps1` afterwards. |
| Changed `compose.yaml` | `docker compose up -d`. Run `setup.ps1` again if `keycloak` or `pg-primary` was recreated. |
| Keycloak was recreated | `setup.ps1`. Dev mode re-imports the realm with new user IDs, so Grafana sign-in fails with "user not found": wipe Grafana's data with `docker compose rm -sf grafana`, `docker volume rm security-prototype_grafana-data`, then `docker compose up -d grafana`. |
| A migration recreated `customers` or `orders` | `setup.ps1` (or `setup-portal.ps1`) to restore the write-audit trigger. |
| Look for leftover temp users | `scripts\stale-users.ps1` (report only; exit code 3 = some found) |
| Wipe everything | `docker compose down -v`, then `Remove-Item .\secrets\openbao_unseal_key, .\secrets\openbao_root_token`. Keep the two `openbao_reconciler_*` files: Docker creates a *directory* in place of a missing secret file. |
| Rotate every secret | Wipe as above, delete `secrets\`, then run `gen-secrets.ps1` again. |

OpenBao and the databases must always be wiped **together**. OpenBao rotated the database admin passwords, so after wiping only one side, nobody knows them.

## 6. Walkthroughs

### 6.1 Request read access (portal)

1. Open http://localhost:8090 and sign in as `bob`. Request `app1` with a ticket (`ABC-123`), a reason and a duration.
2. In a private window, sign in as `carol` and approve the request. Carol cannot approve her own requests.
3. Bob's page shows the remaining time and the OpenBao paths to read. The membership is removed at expiry, checked every 15 s.

### 6.2 Get database credentials and connect to a replica

Start the `bao` CLI in a throwaway container:

```powershell
docker run --rm -it --network security-prototype_lab -p 127.0.0.1:8250:8250 -v security-prototype_pki-ca:/pki-ca:ro -e BAO_ADDR=https://openbao:8200 -e BAO_CACERT=/pki-ca/ca.crt --entrypoint sh openbao/openbao:2.7.2
```

Inside that container, run:

```sh
bao login -method=oidc role=dev listenaddress=0.0.0.0 port=8250 skip_browser=true
# open the printed http://keycloak.localhost:8180/... link and sign in (alice, or bob after approval)
bao read database/creds/app1-pg-ro      # or app1-maria-ro
bao token revoke -self                  # when finished: revokes the token and all its leases
```

Then connect from a client on the `access` network. Only the replicas are reachable from it.

```powershell
docker run --rm -it --network security-prototype_access -v security-prototype_pki-ca:/ca:ro postgres:17 psql "host=pg-replica dbname=app1 user=<username> sslmode=verify-full sslrootcert=/ca/ca.crt"
docker run --rm -it --network security-prototype_access -v security-prototype_pki-ca:/ca:ro mariadb:11.8 mariadb -h maria-replica -u <username> -p --ssl-ca=/ca/ca.crt --ssl-verify-server-cert app1_masked
```

`SELECT * FROM debug.customers` (PostgreSQL) or `SELECT * FROM customers` (MariaDB) shows masked rows. A write, or a read of a base table, is refused.

A grant takes effect only at the developer's **next** OpenBao login. Its removal does not end tokens already issued (D11).

### 6.3 Request write access (PostgreSQL only)

1. In the portal, `bob` requests `app1-write` (at most 60 min). `dave` approves; `carol` cannot.
2. Bob logs in to OpenBao again and runs `bao read database/creds/app1-pg-rw`. The lease lasts 30 minutes and allows one session.
3. Bob connects to the **primary** from the `rw-access` network:

   ```powershell
   docker run --rm -it --network security-prototype_rw-access -v security-prototype_pki-ca:/ca:ro postgres:17 psql "host=pg-primary dbname=app1 user=<username> sslmode=verify-full sslrootcert=/ca/ca.crt"
   ```

Every statement and every changed row reaches the audit store and raises `write_access_*` alerts.

### 6.4 Debug from telemetry instead (Grafana)

Click through http://localhost:8080. Then open http://localhost:3000 and sign in as `alice`. Go to **Explore**, choose **Tempo**, then **Search**, and pick service `web`, `dotnet-api` or `laravel-api`. A trace shows the browser, API and SQL spans. **Logs for this span** opens the matching Loki lines, with e-mail addresses masked.

### 6.5 Read the audit log and the alerts

The store is readable only by mounting its volume read-only in a throwaway container. The `fluent-bit` image has no shell.

```powershell
# latest alerts
docker run --rm --network none -v security-prototype_log-store:/store:ro postgres:17 tail -n 20 /store/alerts.jsonl
# everything one person's temp users did, on every server
docker run --rm --network none -v security-prototype_log-store:/store:ro postgres:17 grep -F v-oidc-alice- /store/audit.jsonl
# as a table
docker run --rm --network none -v security-prototype_log-store:/store:ro postgres:17 tail -n 200 /store/audit.jsonl | ForEach-Object { $_ | ConvertFrom-Json } | Where-Object { $_.user -like 'v-*' } | Format-Table timestamp, source, event, user, client_host, statement -AutoSize -Wrap
```

To map a database username to a person, find the record with `"source":"openbao"`, `"event":"response"` and `"db_username":"<username>"`. Its `user` field is the person. Avoid double quotes in `docker` arguments: Windows PowerShell 5.1 drops them.

## 7. Configuration reference

After a change, apply it with the action in the last column.

| Setting | Where | Default (lab) | Apply with |
|---|---|---|---|
| Read lease TTL / max | `scripts\setup-access.ps1` (`app1-pg-ro`); `scripts\setup-audit.ps1` (`app1-maria-ro`) | 1 h / 4 h | `setup.ps1`. If you change max_ttl, also change `BACKSTOP_MAX_TTL_SECONDS` and the `stale-users.ps1` default. |
| Write lease TTL | `scripts\setup-portal.ps1` (`app1-pg-rw`) | 30 min | `setup.ps1` |
| Who gets read access | Keycloak group `app1-devs` (through the portal) | portal grants | — |
| Who approves | Keycloak groups `app1-approvers`, `app1-write-approvers` | `carol`, `dave` | Keycloak admin |
| Portal durations | `compose.yaml`, `portal`: `Portal__MinDurationMinutes` / `MaxDurationMinutes` | 1 / 240 (production: 60 / 240) | `docker compose up -d portal` |
| Portal check interval | `Portal__ReconcileSeconds` | 15 s | same |
| Sweeper interval | `SWEEP_INTERVAL_SECONDS` on `pg-sweeper`, `maria-sweeper` | 10 s (production: 60) | `docker compose up -d` |
| Reconciler interval | `RECONCILE_INTERVAL_SECONDS` on `lease-reconciler` | 15 s (production: 60) | `docker compose up -d` |
| MariaDB expiry backstop | `BACKSTOP_*` on `maria-replica` | every 15 s, margin 300 s (production: 300 s / 900 s) | `docker compose up -d maria-replica` (purges temp users) |
| PostgreSQL deny list | `PG_DENY_*` on `pg-replica` and `lease-reconciler` (role lists must match) | `app1-pg-ro` | `docker compose up -d` |
| What pgAudit logs | `pgaudit.log` on the server command line in `compose.yaml` | primary `ddl, role`; replica `read, write, ddl, role, misc_set` | recreate the server |
| What server_audit logs | `--server-audit-*` in `compose.yaml` | `CONNECT,QUERY` | recreate the server |
| Alert rules | `config\fluent-bit\audit.lua` | lab rules | `docker compose up -d --force-recreate fluent-bit` |
| Telemetry redaction | `config\telemetry\alloy\config.alloy` | e-mail masked; bodies, queries, SQL params dropped | `--force-recreate alloy` |
| Telemetry retention | `config\telemetry\loki\loki.yaml`, `tempo\tempo.yaml` | 7 days / 72 h | `--force-recreate loki tempo` |
| Memory limits | `mem_limit` per service in `compose.yaml` | stack ≈ 1.9 GiB | `docker compose up -d` |

**To add a developer:** create the user in Keycloak, realm `lab`. Every user is in `lab-users` by default. They request access in the portal. Do not add people to `app1-devs` by hand: the drift check removes them and raises an alert.

**To change a fixed IP address or subnet:** update `compose.yaml`, the `pg_hba` blocks in the same file, the MariaDB host masks (`config\mariadb\*.sh`, `scripts\setup-*.ps1`) and the tests together. They all name the addresses.

## 8. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `setup.ps1` stops at "OpenBao is sealed" or a test says sealed | Run `scripts\unseal.ps1`. |
| `up` fails on a secret, or a path under `secrets\` is a directory | A secret file was missing at `up`, so Docker created a directory in its place. Delete that directory, run `gen-secrets.ps1`, then `up -d` again. |
| `OpenBao is initialized but secrets\openbao_root_token is missing` | The OpenBao volume belongs to an earlier set of secrets. Wipe everything (section 5). |
| `lease-reconciler` logs `action=error` | OpenBao is sealed. It logs `action=recovered` after `unseal.ps1`. |
| Sweepers log connection errors right after `up` | Expected until `setup.ps1` stage 2 has created their accounts. |
| Grafana: "unable to create user: user not found" | Keycloak was recreated. See section 5. |
| `maria-replica` or `pg-replica` restarts in a loop | `docker compose logs <service>`. A half-finished seed or clone is wiped and redone automatically on the next start. |
| Occasional single failure of an app request in `audit-checks.ps1` (95 of 96) | Docker Desktop's port forwarding drops a few Windows PowerShell requests. nginx never sees them. Re-run the suite. |
| Anything else | `docker compose ps -a` (one-shot jobs must show `Exited (0)`), then `docker compose logs <service>`. |
