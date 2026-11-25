# Key decisions

Why the stack is built the way it is. Each decision has an ID (D1 to D13); comments in the code refer to these IDs. To run the stack, see [PLAYBOOK.md](PLAYBOOK.md).

## Context

- **Apps:** an Angular frontend, a .NET 10 API on PostgreSQL 17, and a Laravel 13 API on MariaDB 11.8. Backends and databases are separate, and everything runs in containers. `app1` is a placeholder name.
- **Goal:** harden production database access for developers who need to debug production data. Developer access should be temporary, read-only by default, per person, logged, and limited to the data needed.
- **Constraints:** free and self-hosted. Use no software with user, employee, revenue or instance caps, and depend on no paid-edition features. The organisation has more than 100 people. Docker Desktop is allowed under an existing subscription. Production runs Docker Engine.
- **Lab:** one Windows machine with 8 GB RAM and Docker Desktop (WSL2). The scripts target Windows PowerShell 5.1.

## Tooling

| Chosen | Licence | Role |
|---|---|---|
| OpenBao | MPL-2.0 | Short-lived database credentials, audit log |
| Keycloak | Apache-2.0 | SSO / OIDC. Group membership drives OpenBao policies |
| pgAudit, MariaDB `server_audit` | PostgreSQL / GPL-2.0 | Per-statement audit in each database server |
| Fluent Bit | Apache-2.0 | Audit log shipping |
| Grafana Alloy, Loki, Tempo, Grafana | Apache-2.0 / AGPL-3.0 | Debug telemetry (not the audit store) |
| OpenTelemetry SDKs, Grafana Faro | Apache-2.0 | Traces and logs from the APIs and the browser |

Rejected options:

| Rejected | Reason |
|---|---|
| Teleport | Since v16 the binaries use a commercial licence. They are free only under 100 employees and US$10M revenue. |
| HashiCorp Vault | BUSL, not open source. OpenBao is the open fork. |
| Bytebase, hoop.dev | The free tiers cap users or masking rules. |
| JumpServer | Open-core: database proxying is Enterprise-only. |
| Sentry | Functional Source License. GlitchTip is the open alternative (not built). |
| A home-grown access broker | Credential issuing, revocation and audit integrity are security-critical code that someone must maintain for years. OpenBao issues the credentials; we build only a thin approval portal (D11). |

Optional and not built: Warpgate (bastion), WireGuard (VPN for developer access), GlitchTip, CloudBeaver.

---

## D1. Remove the need for database access first

Most bugs should be reproducible without touching production data. The stack therefore ships debug telemetry: one request in the browser becomes one trace across browser, API and SQL, with the log lines of that request attached (D10). Masked staging data and admin screens for recurring lookups are further options; the lab does not build them.

## D2. Least-privilege application identity, secrets at runtime

- **Two database accounts per app.** `app1_runtime` has DML only (SELECT, INSERT, UPDATE, DELETE). `app1_migrator` owns the schema and runs DDL.
- **Migrations run in one-off containers** (`dotnet-migrate`, `laravel-migrate`) with the migrator credential. The APIs start only after these exit with code 0, and they never see that credential.
- **Every secret is a Docker secret** under `/run/secrets`: passwords, connection strings and the Laravel `APP_KEY`. None is in the compose file, an image or an environment variable. `scripts/gen-secrets.ps1` generates them into `secrets/`, which git ignores.
- **Laravel runs with `APP_ENV=production` and `APP_DEBUG=false`.**

## D3. Network isolation and TLS everywhere

- **No database port is published.** Each backend shares an internal network with its own database only (`app1-pg`, `app1-maria`), so Laravel cannot reach PostgreSQL and the reverse.
- **Fixed subnets and fixed addresses** for OpenBao, the sweepers, the reconciler and the replicas, because `pg_hba.conf` and MariaDB host masks name them. The address plan is at the top of `compose.yaml`.
- **TLS on every database connection**, including replication and OpenBao's admin connections. A lab CA (`pki-init`) issues the certificates. Clients verify the server name: PostgreSQL uses `verify-full`, and MariaDB uses `MASTER_SSL_VERIFY_SERVER_CERT`. It was measured that a connection by IP address is refused.
- **Superusers log in over the local socket only.** On PostgreSQL that is `local all postgres peer` in our own `pg_hba.conf`; the image default allows `host all all all`. On MariaDB it is `root@localhost` only. Default privileges are closed: CONNECT is revoked from PUBLIC, and MariaDB accounts are scoped to a subnet, never `'%'`.

## D4. Just-in-time access: Keycloak + OpenBao

- **A developer logs in to OpenBao personally**, with OIDC through Keycloak, and reads `database/creds/app1-pg-ro` or `app1-maria-ro`. OpenBao creates a temporary user that lasts 1 h by default and 4 h at most, then drops it. Nobody holds permanent production credentials.
- **The Keycloak group `app1-devs` maps to the OpenBao policy `app1-debug`.** Someone outside the group can log in but gets nothing. Every realm user is in a default group (`lab-users`) because Keycloak omits the `groups` claim for a user with no groups, and OpenBao then refuses the login.
- **The person is in the username.** Usernames look like `v-<auth>-<user>-<role>-<unix time>-<random>`. The OpenBao audit log is still the authoritative mapping from person to lease to username. Its response values are HMAC'd by default, so the setup un-HMACs `username` (`audit-non-hmac-response-keys`). The password stays HMAC'd.
- **OpenBao runs from a real config file**, not dev mode: Raft storage, a TLS listener, and an audit device declared in the file. Dev mode loses leases and rotated passwords on restart, and OpenBao 2.3+ refuses audit devices created over the API.
- **OpenBao rotates its own admin password at once (`rotate-root`).** After setup, only OpenBao knows the database admin passwords.
- **Statement and idle timeouts are set on every temp user.** They are guard rails, not controls: the user can override them with `SET`.

## D5. Read-only, masked, and on replicas only

- **Temp users get only masked views**: the PostgreSQL schema `debug` and the MariaDB database `app1_masked`, which mask `email` and `full_name`. OpenBao does not mask data itself.
- **Developers reach the replicas only.** The `access` network contains `pg-replica` and `maria-replica` and no primary. The primary's `pg_hba.conf` also rejects every `debug_ro` member, so heavy debug queries never touch the primary.
- **PostgreSQL temp users are created on the primary.** A hot standby cannot create roles, so the role replicates to the replica, where the developer logs in. Physical replication carries only the SCRAM verifier. Measured lag: 0.2 to 0.9 s.
- **`hot_standby_feedback=off` and `max_standby_streaming_delay=30s` are set on purpose.** With feedback on, a long developer query would hold back VACUUM on the primary and cause bloat, so a read-only developer could degrade production. With it off, such a query is cancelled instead.
- **There is a trap in `pg_hba`.** `bao_admin` holds `debug_ro` WITH ADMIN, so it matches `+debug_ro` lines. Its own line must come first, on the primary and on the replica.

## D6. MariaDB temp users live on the replica only

MariaDB's binary log records `CREATE USER` / `ALTER USER ... IDENTIFIED BY '<pw>'` in clear text, while `server_audit` masks it. So does `GRANT ... IDENTIFIED BY`, and so does `CREATE USER IF NOT EXISTS` on an existing account (measured). With temp users created on the primary, every temp password landed in the primary's binlog and the replica's relay log.

- **OpenBao creates MariaDB temp users on `maria-replica` directly** as `bao_replica_admin`, an account that exists only on the replica. It connects over its own network `bao-replica`, with `?sql_log_bin=0` on every connection. Every statement list starts with a guard that fails if binary logging is on. Without both, a local `CREATE USER` got a replica GTID and the next primary write stopped replication under `gtid_strict_mode` (measured).
- **Primary passwords are set hash-only:** create the account locked, `SET PASSWORD FOR ... = PASSWORD('<pw>')`, then unlock. OpenBao's own rotation uses `SET PASSWORD = PASSWORD('{{password}}')`.
- **The replica's seed load runs with `sql_log_bin=0` and `server_audit_logging=OFF`**, so no password hashes reach its binlog or the audit store.
- **`maria-replica` is not on `bao-admin`.** On that network the name `maria-primary` resolved to the wrong address, and replication broke (measured).
- **To remediate an existing server:** rotate the passwords with a hash-only statement, `FLUSH BINARY LOGS`, wait for the replicas (`MASTER_GTID_WAIT`), then `PURGE BINARY LOGS` on the primary and on each replica. `tests/audit-checks.ps1 -LeakAndPurgeTest` runs this procedure.
- **PostgreSQL is not affected.** pgAudit redacts `PASSWORD`, and OpenBao uses `password_authentication=scram-sha-256`. Keep `log_statement=none`.

## D7. Open sessions outlive revocation, so sweepers end them

Dropping a role or user does not disconnect its sessions on either engine. PostgreSQL `VALID UNTIL` is checked only at login, and a termination on the primary does not replicate.

- **A sweeper per replica** (`pg-sweeper`, `maria-sweeper`) ends sessions of dropped users. The PostgreSQL sweeper also ends sessions of `v-` roles whose `VALID UNTIL` has passed. The lab interval is 10 s; the proposal for production is 60 s.
- **The PostgreSQL sweeper's least privilege:** `pg_signal_backend` and `CONNECT` only. Without `pg_read_all_stats`, other roles' sessions show only `pid` and `usesysid`, so the sweeper is written to need nothing else. Granting that role would expose every query text.
- **The MariaDB sweeper's least privilege:** `PROCESS`, `CONNECTION ADMIN`, and `SELECT (User)` on `mysql.user`. The column grant keeps password hashes unreadable.
- **On MariaDB the revocation statement runs `KILL USER` on the replica itself** (D6), so sessions end about 0.8 s after a revoke. The sweeper is a second line of defence for accounts that vanish without a kill.

## D8. Revocation when a database is unreachable

If the replica (MariaDB) or the primary (PostgreSQL) is down when a lease is revoked or expires, OpenBao retries with backoff. After about 11 minutes the lease becomes irrevocable. Before these backstops, a revoked MariaDB user could log in to a restarted replica for 31 to 57 s. A revoked PostgreSQL role logged in 10 out of 10 times during a 150 s primary outage. Four independent layers close those windows:

1. **Startup purge (MariaDB).** The replica's `init_file` drops every local `v-` user before the server answers any connection. All MariaDB temp users are temporary and replica-local, so this is safe. A developer with a still-valid lease simply requests new credentials.
2. **Expiry backstop (MariaDB).** A replica-local event drops `v-` users older than `max_ttl` plus a margin. It runs as a locked, least-privilege definer with `sql_log_bin=0`. Always write `ALTER DEFINER = ... EVENT`: without the clause, the altering user becomes the definer.
3. **Lease reconciler (both engines).** A small `bao` CLI loop on its own network revokes pending leases (TTL 0 in two passes) and irrevocable leases with `sync=true`. It uses AppRole with a narrow policy whose every rule was tested by removal, batch tokens of 300 s, and a CIDR binding.
4. **PostgreSQL replica deny list.** For a pending or irrevocable lease, the reconciler writes a strictly validated descriptor into a volume that only it can write. A watcher inside `pg-replica` turns it into a `pg_hba` reject pattern, reloads, and terminates the role's sessions. Measured: the revoked role is refused within one reconciler interval plus about 2 s. Roles of the same OpenBao role issued in the same seconds are over-denied, which is accepted.

A report-only detector (`scripts/stale-users.ps1`) lists `v-` users that outlived `max_ttl`.

## D9. Audit everything into a store nobody else can touch

- **Database audit runs on every server, replicas included**, because logs land where the query ran. The primary logs DDL and role changes, not application reads (volume). The replica logs everything a temp user does. pgAudit settings are on the server command line, which outranks `ALTER SYSTEM`. A setting on `debug_ro` would not reach its members. `server_audit` is `FORCE_PLUS_PERMANENT`.
- **Shipping:** every writer logs to its own volume. Fluent Bit mounts them all read-only. It has no network, no Docker socket, runs as non-root with a read-only root file system and no capabilities, and is the only container that mounts `log-store`. A Lua filter normalises the records into `audit.jsonl` and writes alert matches to `alerts.jsonl`.
- **The join that matters** is person (OpenBao audit) → lease → database username → the query on the replica, with the client host.
- **Alert rules (lab form)** include `login_not_allowlisted`, `superuser_login` (which also catches the `docker exec` bypass), `temp_user_denied`, `temp_user_write`, `openbao_request_failed`, the backstop and reconciler alerts, the portal alerts and the write-path alerts. They are listed in `config/fluent-bit/audit.lua`. Nothing sends notifications yet.

## D10. Debug telemetry is separate from the audit trail

- **Alloy is the only entry point.** It receives OTLP from the APIs and Faro from the browser through nginx on the same origin, and it publishes no port.
- **Data is redacted before storage.** Alloy masks e-mail addresses and deletes query strings, bodies and SQL parameter values. The apps add a second layer: SQL is recorded with placeholders only, and handlers log ids and counts, never customer fields. This was tested with sentinel values.
- **Grafana sign-in goes through Keycloak only.** Members of `app1-devs` become Viewers with Explore. Everyone else is refused. Login form, basic auth and anonymous access are off.
- **Telemetry is developer-readable and short-lived** (7 days of logs, 72 h of traces), so it must never hold audit records. No telemetry container mounts an audit volume, and the apps cannot reach Loki, Tempo or Grafana.

## D11. A thin approval portal

OpenBao has no approval workflow, so the portal (`apps/portal`, ASP.NET Core 10 + Angular) adds only that:

1. A developer requests access with a ticket ID, a reason and a duration of 1 to 4 h.
2. A member of `app1-approvers` approves or denies. Nobody can approve their own request, and a denial needs a comment.
3. On approval, the portal adds the requester to the Keycloak group `app1-devs`. At expiry or on early revocation it removes them. A drift check removes any member without an active grant and raises an alert.
4. The developer still logs in to OpenBao personally. **The portal has no OpenBao token and no database access.**

- **The portal's Keycloak service account can change the membership of the managed groups only.** This uses fine-grained admin permissions v2, plus read-only `view-users`, because without it group searches return empty lists. Ten other admin writes were tested and refused.
- **Known limit:** removing a group membership does not end an OpenBao token that was already issued. The next login re-reads the groups and cuts every token of that person; otherwise the token TTL (4 h max) bounds the delay. Credentials already issued live until their lease ends. Closing this gap needs the portal to revoke tokens in OpenBao (not built).

## D12. A rare, audited write path (PostgreSQL only)

The preferred route for a data fix is still a reviewed migration. When that is too slow:

- **The portal app `app1-write`** lasts at most 60 min and needs an approver from `app1-write-approvers`, never the requester. Read approvers cannot see or approve write requests.
- **The OpenBao role `app1-pg-rw` creates the user on the primary.** The lease is 30 minutes and cannot be renewed past that. The user gets one session and is a member of `debug_rw`, which has DML on an explicit table allow-list and nothing else.
- **Write users connect only from the network `rw-access`**, only to `app1`, only over TLS. The replica refuses them, and read users are still refused on the primary.
- **Every write session is audited three ways:** pgAudit on the temp role itself (set by a SECURITY DEFINER guard function; if it fails, no credentials are issued), a row trigger that writes old and new rows to `dev_audit.row_changes`, and the alerts `write_access_login` and `write_access_statement`. Tests confirmed that a write user cannot switch any of these off.
- **Consequences:** the audit store now holds unmasked changed rows, so its access and retention must allow that. Re-run the setup after a migration that recreates a table, because a dropped table loses its trigger. MariaDB has no write path: its temp users live on the replica (D6), so it needs its own design.

## D13. Host access bypasses everything (not built)

Anyone with SSH, the Docker socket or `docker exec` on a production host is effectively a database superuser. Controls for production: a small named ops group, short-lived SSH certificates (OpenBao SSH engine or Warpgate), deployments by pipeline only, no Docker socket in containers, rootless Docker, and off-host shipping of auditd and Docker events. The lab only detects this through the `superuser_login` alert.

---

## Lab-only shortcuts (do not copy to production)

- OpenBao is initialised with one key share. The unseal key and root token are plain files in `secrets/`, and the root token is never revoked.
- Keycloak runs in dev mode over plain HTTP with an in-container database, so a recreated container re-imports the realm with new user IDs. The test passwords are in the realm seed file. The clients `bao-jwt-test` and `portal-test` allow the password grant for the tests.
- The reconciler's AppRole secret ID never expires. Production would use a response-wrapped, short-TTL secret ID or a platform identity.
- The portal allows durations down to 1 minute (production: 60) and accepts Bearer tokens. `alice` is a standing `app1-devs` member. The portal uses HTTP cookies because Keycloak is on HTTP.
- OTLP, Loki and Tempo have no TLS or authentication, and every trace is sampled.
- The log store has no rotation or retention and is reachable by anyone with Docker or host access. Production needs an off-host, append-only store.
- The MariaDB `replicator` has dump privileges for the seed. Its password is in the replica's `master.info`.

## Known limits and residual risks

- Superusers can switch auditing off: PostgreSQL `SET pgaudit.log`, MariaDB `SET GLOBAL server_audit_logging`. Only the `superuser_login` alert covers this.
- Revocation detection on PostgreSQL depends on OpenBao and the reconciler. A revoked role can log in for up to one reconciler interval plus about 2 s. The descriptor volume works on a single host only.
- Every `maria-replica` restart also drops the users of valid leases. A failed `bao lease revoke -sync` is not retried; its user goes at the next replica start or at lease expiry.
- `bao_replica_admin` holds global `CREATE USER`, `READ ONLY ADMIN`, `BINLOG ADMIN` and `CONNECTION ADMIN` on the replica. A compromised OpenBao can alter any replica account.
- With `hot_standby_feedback=off`, long developer queries on the PostgreSQL replica can be cancelled after 30 s of conflict.
- In the measurements, a few Windows PowerShell requests to `localhost:8080` were dropped by Docker Desktop's port forwarding. nginx never saw them. This explains the occasional 95 of 96 result in `audit-checks.ps1`.
- Not built: notifications for alerts, bulk-export detection, a break-glass superuser path, Warpgate, a VPN, a MariaDB write path, and host access controls (D13).

## Open questions for production

- Do read replicas exist in production, or can they be added? Without replicas, the read role points at the primary with firewall, `pg_hba` and timeout limits.
- Which OIDC provider, VPN and ticket system are in use?
- What are the real PostgreSQL and MariaDB versions? PostgreSQL 16 or later is needed for the `CREATEROLE` model used here.
- Where do the audit logs go (existing log infrastructure)?
- Who holds the OpenBao unseal keys?
