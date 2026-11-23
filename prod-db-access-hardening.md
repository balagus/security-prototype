# Production Security, Database and Access Hardening: Proposal and Prototype Plan

Date: 2026-11-17
Revision 8

**Status:** Phases 0 to 4 were executed in the prototype: sections 4.A, 4.B, 4.C (replica path), 4.E (database audit and shipping) and 5. Test counts against the phase 4 stack: 13 smoke, 38 hardening, 84 access, 95 replica, 96 audit, 129 revocation checks (133 with the opt-in irrevocable-lease test), all passing on a from-scratch stack (re-run independently). The MariaDB binary-log password leak found in phase 4 is fixed and tested (4.E, 5.3). Phase 5 (debug telemetry: traces and logs in Grafana, redacted, separate from the audit store) was executed on 2026-11-23: 27 phase 5 checks and 13 smoke checks pass; the phase 4 suite on the phase 5 stack passes 94 of 96 (two app-request checks hit dropped host connections, 7.5). The approval portal (phase 6, 4.C "Approval design") was built and tested on 2026-11-23 as an add-on to the phase 5 stack: 83 phase 6 checks pass. Warpgate and the break-glass role and alert (rest of phase 6) have **not** been executed. Host access controls (4.D) have **not** been executed. Items still marked "to test" remain unverified.

**Main open problem:** none on revocation. On PostgreSQL a role revoked while the primary is down is refused by the replica within one reconciler interval plus 2 s (replica-side deny list, 5.4).

---

## 1. Scope and assumptions

**Scope.** Harden security, database access and production access for the existing containerized applications, and build a basic simulated environment to prove the design.

The applications:
- Angular frontend.
- .NET 10 backend with PostgreSQL.
- Laravel 13 backend with MariaDB.
- Separate backends and separate databases. Everything runs in containers.

Five workstreams:

| ID | Workstream | Goal |
|---|---|---|
| A | Application database identity | Apps use least-privilege accounts; secrets are injected at runtime. |
| B | Network and database-server hardening | Databases are unreachable except by their own backend; TLS everywhere. |
| C | Developer just-in-time access | Temporary, read-only, per-person, masked, logged access for debugging. |
| D | Host and container access | Control who can reach production hosts, the Docker socket and `docker exec`. |
| E | Audit and alerting | Tamper-resistant logs that map every query to a person; alerts on misuse. |

**Out of scope here:** frontend and API hardening (authentication and authorization in the APIs, CSP, CORS, security headers). This is a separate workstream.

**Licensing rule (from the owner).** Use only software with no licensing limitations: no caps on users, employees, revenue or instances, and no dependence on paid-edition features. Prefer open source. One exception: Docker. A Docker enterprise subscription is available, so Docker Desktop is allowed.

**Naming.** `app1` is a placeholder. In the examples the PostgreSQL database belongs to the .NET API and the MariaDB database to the Laravel API. Both are called `app1` to keep the configuration parallel. Addresses and passwords are `<placeholders>`.

### Assumptions to confirm with the owner

These are not in the brief.

- Read replicas exist in production, or can be added.
- An SSO / OIDC provider is acceptable (Keycloak by default).
- A VPN for developer access is acceptable.
- A ticket system exists, so access requests can carry a ticket ID as the reason.
- EU / GDPR applies.
- Organization size (number of developers and operators who need access).

---

## 2. Principles

Developers should almost never touch production directly. When they do, access should be **temporary, read-only, per-person, logged, and limited to the data needed**.

1. **Remove the need first**
   - Structured logs, tracing (OpenTelemetry), error tracking (GlitchTip).
   - Staging with anonymized or masked copies of production data.
   - Admin and support screens in the apps for recurring lookups.
2. **Grant access just in time**
   - Request with a reason (ticket ID), approval, automatic expiry (1-4 h).
   - No permanent production credentials for anyone.
3. **Read-only by default, on a read replica**
   - A replica protects the primary from heavy queries, but only conditionally. On PostgreSQL a long replica query is either cancelled after `max_standby_streaming_delay`, or, with `hot_standby_feedback = on`, it holds back cleanup and causes bloat on the primary.
   - Set statement timeouts for debug sessions in both cases.
   - Write access is a separate, rarer request with stronger approval.
4. **Per-person identity**
   - SSO through Keycloak. No shared logins, never the app's service account.
5. **No direct network exposure**
   - WireGuard VPN. Databases have no published ports.
6. **Mask sensitive data**
   - Views over PII and payment data. OpenBao does *not* mask data itself.
7. **Audit everything**
   - Per-user query logs shipped to a store developers cannot edit or delete.
   - Review access regularly, alert on bulk exports.
8. **Data fixes go through code review**
   - Reviewed script or migration, run by a pipeline or second person, in a transaction, tested on staging, with a backup of the affected rows.
9. **The database controls are only as strong as host access**
   - Anyone with SSH, the Docker socket or `docker exec` on a production host can bypass all of the above. See workstream D.

GDPR angle (EU): data minimization means masking by default; audit logs show who accessed personal data and why.

---

## 3. Tooling

### 3.1 Selected

| Tool | Licence | Role |
|---|---|---|
| OpenBao | MPL-2.0 | Issues short-lived DB credentials, SSH certificates, stores break-glass secrets. Audit log. |
| Keycloak | Apache-2.0 | SSO / OIDC provider. Group membership drives OpenBao policies. |
| PostgreSQL | PostgreSQL License | Database for the .NET API. |
| pgAudit | PostgreSQL License | Per-session and per-object audit logging in PostgreSQL. |
| MariaDB Community Server + bundled `server_audit` plugin | GPL-2.0 | Database for the Laravel API, with audit logging. |
| WireGuard | GPL-2.0 | VPN for developer and operator access. |
| Fluent Bit | Apache-2.0 | Ships logs off the hosts. |
| Grafana Alloy | Apache-2.0 | Debug telemetry collector (OTLP and Faro); redacts personal data before storage (phase 5). |
| Grafana, Loki, Tempo | AGPL-3.0 | Debug telemetry: dashboards and Explore, logs, traces (phase 5). Not the audit store. |
| OpenTelemetry SDKs (.NET, PHP), Grafana Faro Web SDK | Apache-2.0 | Traces and logs from the APIs and the browser (phase 5). |
| nginx | BSD-2-Clause | Serves the Angular app, reverse proxy to the APIs. |
| .NET / Npgsql / Laravel / Angular | MIT / PostgreSQL License / MIT / MIT | Application stack. |
| ASP.NET Core OpenID Connect and JwtBearer handlers, Microsoft.Data.Sqlite (SQLite: public domain) | MIT | Approval portal (phase 6). |
| Docker Engine | Apache-2.0 | Container runtime. Docker Desktop is commercial, covered by the existing subscription. |

### 3.2 Optional

| Tool | Licence | Role |
|---|---|---|
| Warpgate | Apache-2.0 | Bastion. Gives query **logs** for database sessions; replayable recording only for SSH, Kubernetes, RDP and VNC. |
| GlitchTip | MIT | Error tracking (Sentry-compatible SDKs). |
| OpenSearch | Apache-2.0 | Alternative central log store. |
| CloudBeaver Community | Apache-2.0 | Web SQL client, if developers should not need a local client. |

**Licence check.** Every licence in 3.1 and 3.2 was confirmed on 2026-11-16 against the project's own LICENSE file or official site. Notes:

- Docker Desktop is the only proprietary item (free only under 250 employees and under US$10M revenue). It is used on the lab machine under the Docker exception. Production hosts run Docker Engine.
- `server_audit` ships with MariaDB Community Server but is not loaded by default (`plugin_load_add = server_audit`). It is not the paid MariaDB Enterprise Audit plugin.
- Grafana, CloudBeaver and nginx also have paid editions (Grafana Enterprise, CloudBeaver Enterprise, NGINX Plus). Nothing here depends on them.
- GlitchTip: only the backend repository licence was checked.
- Phase 5 additions (Alloy, Grafana, Loki, Tempo, OpenTelemetry .NET and PHP, Faro Web SDK, Npgsql.OpenTelemetry) were checked on 2026-11-23 against each project's GitHub licence record and the package registries (NuGet, Packagist, npm). Grafana moved from 3.2 to 3.1 with phase 5.

### 3.3 Excluded

| Tool | Reason |
|---|---|
| Teleport | Since v16 the official binaries use a commercial Community Edition licence, free only under 100 employees and under US$10M revenue. Building from source (AGPLv3) means compiling and distributing it ourselves. |
| HashiCorp Vault | Business Source License (BUSL), not open source. OpenBao is the open fork. |
| Bytebase | Community edition capped at 20 users / 10 instances; masking and audit log are paid. |
| hoop.dev | MIT core, but the free tier is limited to 1 masking rule and 1 guardrail. |
| JumpServer | Open-core (GPLv3): the database protocol proxy is listed as Enterprise-only, and database support in the community edition could not be confirmed. |
| Sentry | Functional Source License, not open source. GlitchTip replaces it. |
| Headscale | BSD-3 itself, but aimed at small single-tailnet use, and it depends on Tailscale clients whose Windows and macOS GUIs are proprietary. Plain WireGuard is used instead. |
| Entra ID | Proprietary paid service. Keycloak is the default; any existing OIDC provider can be substituted. |

### 3.4 Should we build our own access broker?

**Usually no.** A custom broker means writing security-critical software (credential issuing, revocation, audit integrity) that must be maintained for years. Instead:

- Use **OpenBao for credential issuing**: keep the security logic there.
- Build only a **thin internal portal** (C# + Angular fits the existing stack) for request and approval. See 4.C.
- Build more only if a hard requirement (unusual database, compliance workflow) rules out existing tools.

---

## 4. Architecture

### 4.A Application database identity

Per app, two database accounts:

| Account | Used by | Privileges |
|---|---|---|
| `app1_runtime` | The running API | DML (`SELECT`, `INSERT`, `UPDATE`, `DELETE`) on its own schema only. No DDL. Not superuser. Not owner. |
| `app1_migrator` | The deployment pipeline only | Owns the schema, runs DDL. |

Migrations run as a pipeline step, not at app startup:
- .NET: EF Core migrations (for example a migration bundle) run by the pipeline with the migrator credential.
- Laravel: `php artisan migrate --force` run by the pipeline as a one-off container with the migrator credential.
- The running app never holds the migrator credential.

PostgreSQL sketch (to test):

```sql
CREATE ROLE app1_migrator LOGIN PASSWORD '<migrator-password>';
CREATE ROLE app1_runtime  LOGIN PASSWORD '<runtime-password>';
ALTER DATABASE app1 OWNER TO app1_migrator;   -- PG 15+: also owns schema public via pg_database_owner
GRANT USAGE ON SCHEMA public TO app1_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE app1_migrator IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app1_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE app1_migrator IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO app1_runtime;
```

MariaDB follows the same split: `app1_runtime` gets `SELECT, INSERT, UPDATE, DELETE ON app1.*`; `app1_migrator` adds `CREATE, ALTER, DROP, INDEX, REFERENCES`. Both are scoped to a subnet and `REQUIRE SSL`.

MariaDB passwords are never set with `IDENTIFIED BY`: the binary log would hold them in clear text (4.E). Create the account locked, set the password with `SET PASSWORD`, then unlock:

```sql
CREATE USER 'app1_runtime'@'<app-subnet mask>' REQUIRE SSL ACCOUNT LOCK;
SET PASSWORD FOR 'app1_runtime'@'<app-subnet mask>' = PASSWORD('<runtime-password>');
ALTER USER 'app1_runtime'@'<app-subnet mask>' ACCOUNT UNLOCK;
-- same sequence for app1_migrator@'<pipeline-net mask>' with '<migrator-password>'
```

On the primaries, the replication and sweeper accounts follow the same rules (see 5.1 and 5.4).

**Secrets.** Injected at runtime as Docker secrets (files under `/run/secrets`). Never baked into images, compose files or committed `.env` files.

- .NET: read with the KeyPerFile configuration provider, `builder.Configuration.AddKeyPerFile("/run/secrets", optional: true)`. A secret file named `ConnectionStrings__App1` becomes the key `ConnectionStrings:App1`.

- Laravel: an entrypoint script exports the secret file content into the environment before PHP-FPM starts (to test).

  ```sh
  #!/bin/sh
  set -eu
  export DB_PASSWORD="$(cat /run/secrets/app1_db_password)"
  exec "$@"
  ```

  To test: PHP-FPM workers only see the variable if `clear_env = no` in the pool configuration. Do not run `php artisan config:cache` at image build time with real secrets present, or they end up in the image.

**Later option.** OpenBao database **static roles** rotate the runtime password on a schedule, delivered to the container by OpenBao Agent. Dynamic per-lease credentials for apps are not recommended at first: connection pools hold connections across credential changes and need extra handling.

### 4.B Network and database-server hardening

**No published DB ports.** Databases are reachable only on internal Docker networks.

| Network | `internal` | Members | Purpose |
|---|---|---|---|
| `edge` | no | nginx, WireGuard endpoint | Public entry point for the apps and the VPN port. |
| `web` | yes | nginx, .NET API, Laravel API | nginx to APIs. |
| `app1-pg` | yes | .NET API, pg-primary | One network per backend + DB pair. |
| `app1-maria` | yes | Laravel API, maria-primary | Laravel cannot reach PostgreSQL and vice versa. |
| `pg-repl` | yes | pg-primary, pg-replica | Replication traffic. |
| `maria-repl` | yes | maria-primary, maria-replica | Replication traffic. |
| `bao-admin` | yes | OpenBao, pg-primary, maria-primary | OpenBao creates PostgreSQL temp users on pg-primary. maria-primary is reached only for lab probe roles. |
| `bao-replica` | yes | OpenBao, maria-replica | OpenBao creates MariaDB temp users on the replica. |
| `access` | yes | pg-replica, maria-replica, OpenBao, Keycloak, WireGuard endpoint, sweepers | Developer access. Of the databases, only replicas are reachable. |

Give OpenBao and the sweepers fixed addresses (`ipv4_address`) so `pg_hba.conf` and MariaDB host masks can name them.

The MariaDB replica must not join `bao-admin`. The primary's name then resolved to its `bao-admin` address inside the replica, the replication IO thread connected from that address, the primary refused it, and replication stopped. Hence the dedicated `bao-replica` network.

**TLS for all DB connections**, including OpenBao to DB and replication.
- PostgreSQL: `ssl = on`; every remote line in `pg_hba.conf` is `hostssl` with `scram-sha-256`. Replicas connect with `sslmode=verify-full` in `primary_conninfo`.
- MariaDB: `require_secure_transport=ON`; every account `REQUIRE SSL`. Replicas use `MASTER_SSL=1` and verify the server certificate.
- Verified in phase 3: pointing `MASTER_HOST` at the primary's IP address leaves the IO thread in "Connecting" with "SSL certificate validation failure". The replication account is also refused from other addresses. PostgreSQL `verify-full` likewise refuses a connection by IP.
- In the lab, a script creates a private CA and server certificates.

**Superuser accounts only over the local socket.**
- PostgreSQL: `local all postgres peer`; no network line for `postgres`. Replace the image's default `pg_hba.conf` (it allows `host all all all`) with our own via `hba_file`.
- MariaDB: `root@localhost` with `unix_socket`; no `root@'%'`. With the official image, set `MARIADB_ROOT_HOST=localhost` (to test).

**Default privileges closed.**
- PostgreSQL: `REVOKE CONNECT, TEMPORARY ON DATABASE ... FROM PUBLIC` and `REVOKE CREATE ON SCHEMA public FROM PUBLIC`.
- MariaDB: accounts scoped to a subnet, never `'%'`. Host masks use the netmask form, for example `'10.20.0.0/255.255.255.0'`.
- Replicas: MariaDB runs `read_only=ON`; PostgreSQL runs as hot standby (read-only by design).

**Backups.** Encrypted, access-controlled backups are required but outside the prototype. Backups bypass masking: anyone who can read a backup can read all PII.

### 4.C Developer just-in-time access

```
Developer ──WireGuard──► access network
     │
     ├─ (optional) approval portal: ticket ID + approver
     │        └─ adds time-boxed Keycloak group membership (app1-devs)
     │
     ├─ OIDC login (Keycloak) ──► OpenBao
     │                              │  policy by Keycloak group
     │                              ▼
     │                    database secrets engine, TTL 1-4 h
     │        PostgreSQL: temp user on the PRIMARY ──► replicates (WAL)
     │        MariaDB:    temp user on the REPLICA only (sql_log_bin = 0)
     │                              │
     │                              ▼
     └──── connects with temp user ──► REPLICA only
                                      │
              pgAudit / server_audit ─┼─► Fluent Bit ──► central log store
              OpenBao audit log ──────┘
```

#### Where OpenBao connects

The two engines differ.

**PostgreSQL: the primary.** Creating users on a hot standby fails (not tested). The temp user is created on the primary and **replicates to the replica**, where the developer connects. WAL carries only the SCRAM verifier. This is true only for **physical streaming replication**. Logical replication does not copy roles.

**MariaDB: each replica, directly.** OpenBao connects to the replica over `bao-replica` with `sql_log_bin = 0` in the connection URL (5.2). The temp user never exists on the primary and is never binlogged. Creating users on a replica diverges from replication only if the statements are binlogged. While `sql_log_bin = 0` holds and the guard in every statement list is in place (5.3), they are not.

Consequences:
- PostgreSQL: replication lag delays new credentials. Handle with a retry, or a short wait in the portal. Measured in the lab: 0.2 to 0.9 s (see 5.4).
- PostgreSQL: revocation also replicates, so it is not instant on the replica. Open sessions need the sweeper (5.4).
- MariaDB: no replication step. Credentials give a working login on the replica in under 2 s, and revocation ends sessions in about 0.8 s (5.4).
- MariaDB: one OpenBao connection and role per replica. Not built for more than one.
- MariaDB: a replica outage delays OpenBao's revocation, but it no longer leaves a working login. The replica drops every temp user at each start before it answers any connection (startup purge). A replica-local event drops temp users older than `max_ttl` plus a margin. A lease reconciler completes pending and irrevocable revocations once the replica is reachable again (5.4). A replica restart also drops the users of still-valid leases; those developers request new credentials.
- PostgreSQL: if the primary is down when a lease is revoked, the role stays on the replica, but the lease reconciler writes a deny descriptor and the replica's watcher rejects it in pg_hba and terminates its sessions, within one reconciler interval plus 2 s (measured 3.8 to 12.7 s, lab interval 15 s). A role issued in the same seconds by the same OpenBao role is refused too (accepted over-deny). Expiry needs nothing: VALID UNTIL replicates and the standby enforces it. When the primary returns, the reconciler revokes the lease, the DROP ROLE replicates and the deny entry is released (5.4).
- MariaDB: a re-seeded replica loses its temp users. This is acceptable. `DROP USER IF EXISTS` keeps revocation working.

**Fallback if production has no replicas.** Point the read-only role at the primary, restricted by firewall and `pg_hba.conf` / host mask, with forced timeouts and connection limits. Add replicas later.

#### Approval design (built and tested in phase 6)

OpenBao has no approval feature. The thin portal (C# API + Angular, `prototype/apps/portal`) fills that gap:

1. Developer requests access: app, ticket ID, reason, duration (1 to 4 h).
2. An approver (Keycloak group `app1-approvers`) confirms or denies. Nobody can approve their own request. The portal records ticket ID and approver.
3. The portal adds the developer to the Keycloak group `app1-devs` through the Keycloak admin API, using a service account limited to group management.
4. On expiry or early revocation, the portal removes the membership.
5. The developer still logs in to OpenBao personally and fetches credentials. The OpenBao identity is the person, not the portal. The portal has no OpenBao token and no database access.
6. A drift check removes any `app1-devs` member without an approved, active grant and raises an alert.

Measured in the lab (2026-11-23, `tests/phase6-checks.ps1`, 83 checks):

- Approval to working OpenBao credentials: 2.3 to 2.6 s. Membership removed 4.9 to 8.3 s after expiry, with a 15 s check interval. An out-of-band membership was removed after 12.7 to 13.7 s.
- Keycloak in dev mode keeps its database inside the container. A recreated container re-imports the realm with new user IDs, and Grafana's stored sign-in links then fail (measured). The add-on therefore never redefines Keycloak; the setup attaches it to the portal network at runtime. The portal looks up group IDs again on any 404, so a stale ID never turns a removal into a no-op.
- **Removal is not instant in OpenBao.** A token issued before the removal keeps reading credentials, and `bao token renew` does not change that. The developer's next login re-reads the groups and cuts **every** token of that person, because external group membership belongs to the OpenBao entity. Without a new login, the token TTL bounds the delay (4 h max). Database credentials already issued live until their lease ends. Closing this gap would need the portal to revoke the person's tokens or leases in OpenBao, which needs an OpenBao token with that right. Not built.
- **Service account limits (Keycloak 26.8.2, fine-grained admin permissions v2).** Two permissions are needed for a membership change: Groups `app1-devs` `manage-membership` and Users `manage-group-membership`. With those alone, the group search and group member endpoints return empty lists. The account therefore also has the read-only `view-users` role, so it can read the whole user directory. Writes are limited to `app1-devs`; ten other admin writes were tested and refused. The token also needs the `kc-admin-api` client scope (audience of the admin API), or every call returns 401.
- Every portal action is shipped to the audit store with ticket, requester, approver and group, next to the OpenBao record that maps the person to the database user. There are five new alert rules.

#### Write and break-glass path

- A separate OpenBao role `app1-pg-rw` (TTL 30 min, on the primary) behind a different group that needs second-person approval.
- The preferred route for data fixes remains a reviewed migration (principle 8).
- An emergency superuser password is stored in OpenBao KV under a path readable only by a break-glass policy. Every read raises an alert.

### 4.D Host and container access

Anyone with SSH, the Docker socket or `docker exec` on a production host is effectively database superuser. They can read the secret files, connect through the local socket, or copy the data volume. This bypasses workstream C completely.

Controls:
- A small, named ops group. Nobody else has host access.
- SSH with short-lived certificates signed by OpenBao's SSH secrets engine, or Warpgate for recorded SSH sessions.
- Deployments by pipeline, not by people.
- Never mount the Docker socket into containers.
- Rootless Docker or `userns-remap`.
- Log `docker exec` through auditd and Docker events, and ship those logs off the host. The prototype ships neither: Docker Desktop has no auditd, and Docker events need the Docker socket, which conflicts with the rule above. In the lab, `docker exec` shows up only as a superuser login (4.E, Alerts).
- Alert on any DB login that is neither an app account nor a temp (`v-`) account.

Residual risk remains: host root can disable local logging. Off-host shipping and alerts give detection, not prevention.

### 4.E Audit and alerting

**Person mapping.** The OpenBao audit log is the **authoritative** mapping of person to lease to database username. The DB username is a convenience for reading logs.

The audit log HMACs every response value by default, including the generated database username, so the mapping does not work out of the box. Tune the secrets engine:

```bash
bao secrets tune -audit-non-hmac-response-keys=username database/
```

The password stays HMAC'd (verified). To make every entry name the person, also set `claim_mappings` on the auth role (see 5.5).

The log store (see Shipping) gives the join this design relies on, verified by test: person (OpenBao audit) → lease id → generated username → the query on the replica, with client host.

**Database audit on every server.**
- pgAudit and `server_audit` must be installed and configured on **each** server, including replicas. Configuration files are per server.
- Logs land on the server where the query ran. Developer queries therefore appear on the replicas.
- Settings applied with `ALTER ROLE debug_ro SET ...` are **not** inherited by member roles. Configure auditing in the server configuration, not on `debug_ro`.
- Keep `%u %h` in `log_line_prefix`. `jsonlog` carries user, host, pid and timestamp natively, so the prefix matters only for text output.
- The official `postgres` image does not include pgAudit. The prototype uses a small image `FROM postgres:17` plus `postgresql-17-pgaudit` from the PGDG apt repository.
- `CREATE EXTENSION pgaudit` is not needed for session logging. Without it, DDL records have an empty object type and name.

**pgAudit configuration (prototype).** Settings are on the server command line. They outrank `ALTER SYSTEM` (tested).

```
shared_preload_libraries = pgaudit
logging_collector = on
log_destination = jsonlog
log_file_mode = 0640
log_connections = on
log_disconnections = on
log_statement = none
log_line_prefix = '%m [%p] user=%u db=%d host=%h app=%a '
pgaudit.log = 'ddl, role'                              # primary
pgaudit.log = 'read, write, ddl, role, misc_set'       # replica (developer queries land here)
pgaudit.log_catalog = on
pgaudit.log_relation = off
pgaudit.log_parameter = off
```

Role settings replicate:

```sql
ALTER ROLE postgres SET pgaudit.log = 'read, write, ddl, role, misc_set';   -- everything a superuser does
ALTER ROLE postgres SET pgaudit.log_catalog = off;
ALTER ROLE session_sweeper SET pgaudit.log_catalog = off;
```

- Application reads on the primary are not audited. This is a deliberate choice, for volume.
- A temp user cannot change any `pgaudit.*` setting ("permission denied to set parameter"; tested).
- A superuser can run `SET pgaudit.log = 'none'` in a session (tested). This residual risk is covered only by the superuser-login alert.

**`server_audit` configuration (prototype).** Both MariaDB servers:

```
plugin_load_add = server_audit
server_audit = FORCE_PLUS_PERMANENT
server_audit_logging = ON
server_audit_output_type = file
server_audit_events = CONNECT,QUERY
server_audit_query_log_limit = 4096
server_audit_file_rotate_size = 10485760
server_audit_file_rotations = 9
general_log = OFF
slow_query_log = OFF
server_audit_excl_users = healthcheck,app1_runtime      # primary
server_audit_excl_users = healthcheck,session_sweeper   # replica
```

Measured:
- `QUERY_DDL,QUERY_DCL` does not include `ALTER USER` or `SET PASSWORD`, so `QUERY` is needed.
- `server_audit_excl_users` does not suppress CONNECT events.
- Statements replicated to the replica are not audited on the replica.
- `UNINSTALL PLUGIN server_audit` fails with `FORCE_PLUS_PERMANENT`, but root can still `SET GLOBAL server_audit_logging = OFF`. The OFF and ON are logged; statements in between are not.
- A temp user cannot change it.
- `server_audit` truncates statements at the query log limit and has 1-second timestamps.
- On the replica, `server_audit` records `bao_replica_admin`'s CREATE and DROP (password masked) and the temp user's queries. The shipping and the person → lease → username → query join still work.
- `init_file` statements are audited with user `boot`. Statements run by an event are not audited by `server_audit` (measured), so the shipped backstop line is the only record of the event's drops.

**Password leak in logs: PostgreSQL.** Not affected, with the settings above.
- pgAudit 17.1 redacts on its own. It writes `CREATE ROLE "v-..." LOGIN PASSWORD <REDACTED>` and drops the rest of the statement. Tested for CREATE/ALTER ROLE/USER, with `WITH`, `ENCRYPTED`, options before and after `PASSWORD`, for `bao_admin` and `postgres`, with and without SCRAM.
- The leak comes from PostgreSQL's core statement logging. With `log_statement = 'ddl'` for `bao_admin` and `password_authentication=password`, the clear-text temp password was in the primary's log and was shipped. With `password_authentication=scram-sha-256` the same line holds only the SCRAM verifier.
- Root rotation is logged as `PASSWORD <REDACTED>`. Failed logins never logged the attempted password (PostgreSQL and MariaDB).
- WAL carries the SCRAM verifier, not the password.
- **Recommendation:** keep `log_statement = none`, keep the pgAudit `role` class for everyone including `bao_admin` (role creation and drops stay on record), and keep `password_authentication=scram-sha-256`.
- Cost: the redaction drops `VALID UNTIL` and `CONNECTION LIMIT` from the audit record. The OpenBao audit log holds the lease TTL instead.
- Not tested: the `STATEMENT` line written for a failed `CREATE ROLE` (`log_min_error_statement`).

**Password leak in logs: MariaDB (fixed, tested).** `server_audit` masks passwords (`IDENTIFIED BY *****`), but the **binary log does not**, for some statement forms. Found in phase 4: every `CREATE USER ... IDENTIFIED BY '<pw>'` from OpenBao went verbatim into the primary's binary log and the replica's relay log, and so did the init and setup passwords. Anyone able to read the binlog files could recover them.

How MariaDB 11.8 writes password statements to the binary log (measured):

| Form | Binary log |
|---|---|
| `CREATE USER` / `ALTER USER ... IDENTIFIED BY '<pw>'` | clear text |
| `IDENTIFIED VIA mysql_native_password USING PASSWORD('<pw>')` | clear text |
| `GRANT ... IDENTIFIED BY '<pw>'` | clear text |
| `CREATE USER IF NOT EXISTS ... IDENTIFIED BY` on an existing account | clear text, on every run |
| `SET PASSWORD FOR ... = PASSWORD('<pw>')` | hash only |
| `IDENTIFIED BY PASSWORD '<hash>'` | hash only |

`server_audit` masks all of these forms.

**Rule.** On a MariaDB server with a binary log, never set a password with `IDENTIFIED BY`. Create the account `ACCOUNT LOCK`, set the password with `SET PASSWORD FOR ... = PASSWORD('<pw>')`, then `ALTER USER ... ACCOUNT UNLOCK`.
- Applied to every MariaDB account: `app1_runtime`, `app1_migrator`, `bao_admin`, `replicator`, `session_sweeper` (4.A, 5.1). The prototype does this for all of them (tested).
- Test scripts must follow it too. A lab test probe account created with `IDENTIFIED BY` was found in the binlogs by an independent pattern scan, and fixed.
- Root rotation: `root_rotation_statements` uses `SET PASSWORD = PASSWORD('{{password}}')`. The earlier `ALTER USER ... IDENTIFIED BY` form leaked the new `bao_admin` password; the test recovered it and logged in with it (see 5.2).
- `SET PASSWORD FOR` another account needs `UPDATE` on `mysql.*`, which 5.1 rules out for `bao_admin` (tested). Temp users therefore need the replica-only design below.

**Temp users: created on the replica only, never binlogged.** PostgreSQL is unchanged.
- OpenBao has a second MariaDB connection, `app1-maria-replica`, to the replica over the internal network `bao-replica` (4.B).
- `sql_log_bin=0` is set in the connection URL. Every statement list begins with a guard that fails closed if binary logging is on (5.2, 5.3).
- The account `bao_replica_admin` exists only on the replica (5.1). It cannot log in to the primary and has no rows or grants there.
- The replica now has its own binary log (`log_bin`, `log_slave_updates = ON`, `binlog_format = ROW`, 7-day expiry). Before, it had none. `sql_log_bin=0` keeps the local user statements out of it.
- Replication stayed healthy and the application's writes kept replicating after many temp users were created and dropped (tested).
- Proof: a pattern scan of every decoded binary log and relay log finds no temp password.

**Remediating an existing server** whose binary logs already hold passwords (tested in the lab):
1. Rotate every affected password with a hash-only statement.
2. `FLUSH BINARY LOGS` on the primary.
3. Wait until every replica has applied the position (`MASTER_GTID_WAIT`).
4. `PURGE BINARY LOGS TO '<current file>'` on the primary.
5. On each replica, `FLUSH RELAY LOGS` (with `relay_log_purge` on, old relay logs are removed), then `FLUSH BINARY LOGS` and `PURGE BINARY LOGS TO`.

Replication kept running and nothing was left.

**Seed of a new replica.** The dump is loaded with `sql_log_bin = 0` and with `server_audit_logging` switched OFF for the load only, in the image's init server (which has no network), then ON. From scratch, the replica's audit log and the store contain no `INSERT INTO global_priv` and no password hashes. The OFF and ON statements stay in the log as a record.

Not done: binlog and relay-log encryption at rest (`encrypt_binlog = ON`) and `REPLICATION SLAVE` / `BINLOG MONITOR` restricted to the replicator. The fix above does not depend on them.

**Shipping.** One Fluent Bit container (5.1.5, official image, pinned) tails the logs and writes to a store that nothing else mounts.

Container hardening:
- `network_mode: none`, non-root user, read-only root file system, all capabilities dropped, 128 MB limit (uses about 20 MB).
- No Docker socket is mounted.

Flow:
- Databases, OpenBao and the sweepers write log files to their own volumes. Fluent Bit mounts each of them **read-only**.
- Sources: PostgreSQL jsonlog, `server_audit` text (parsed by regex), OpenBao audit JSON, sweeper logs, the MariaDB replica's backstop lines (one file per startup purge and per expiry run that dropped users, written by the server with `SELECT ... INTO OUTFILE` into its `--secure-file-priv` directory on its own audit volume), the lease reconciler's log (5.4) and pg-replica's deny-list watcher log (`pg-replica-log/pg-deny/`). The OpenBao audit file is written with mode 0640 to a group-readable volume.
- A Lua filter normalises records to JSON lines: timestamp, source server, engine, user, client host, event, statement.
- The store volume is mounted **only** by Fluent Bit (verified by inspecting every container's mounts).
- Healthcheck connect and disconnect records are dropped by the shipper (about 100k lines a day per server).

Measured:

| What | PostgreSQL | MariaDB |
|---|---|---|
| Shipping latency | 0.3 to 1.0 s | about 1.2 s (±1 s, timestamp resolution) |
| Store volume, one developer session with one query | about 2 KB (5 records) | about 0.9 KB (3 records) |
| Per application request | 0 to about 0.1 KB on the primary (the .NET connection pool usually reuses a logged-in connection, and application reads are not audited) | about 0.5 KB (Laravel opens one connection per request; CONNECT and DISCONNECT are always logged) |

Not shipped: auditd and Docker events (see 4.D).

**Debug telemetry is a separate pipeline (phase 5).** Application traces and logs (OpenTelemetry, Faro) go through Grafana Alloy to Loki and Tempo, which developers read in Grafana. That pipeline is developer-readable, redacted and short-lived (7 days of logs, 72 hours of traces in the lab), so it is **not** part of the audit trail and never receives audit records. It shares no volume or network with Fluent Bit and the store (tested). Redaction happens twice: the apps record SQL only in parameterized form and log no customer fields, and Alloy masks e-mail addresses and deletes query strings, bodies and SQL parameter values before storage (tested with sentinel values).

**Alerts (lab form).** Fluent Bit rules write an alerts stream to a separate file:

| Rule | Fires on |
|---|---|
| `login_not_allowlisted` | A login by an account not on the allowlist: app accounts, `bao_admin`, `bao_replica_admin`, `session_sweeper`, `replicator`, `postgres`, MariaDB `healthcheck` and `root`, any `v-` user. |
| `superuser_login` | Any login of `postgres` or MariaDB `root`, local or network. The PostgreSQL healthcheck is excluded, identified by `application_name`, which a local superuser could fake. |
| `temp_user_denied` | Permission and read-only errors for a temp user. |
| `temp_user_write` | A write statement by a temp user. |
| `openbao_request_failed` | An OpenBao error response. A stand-in for "audit device failure". |
| `replica_startup_purge` | The replica dropped one or more `v-` users at startup. |
| `replica_expiry_backstop` | The replica dropped `v-` users older than `max_ttl` plus the margin: OpenBao failed to revoke them. |
| `irrevocable_lease_found` | The reconciler found an irrevocable database lease. |
| `revocation_retried_by_reconciler` | The reconciler re-revoked a pending or irrevocable lease. Fires on every attempt, outcome ok or failed. |
| `pg_replica_deny_applied` | pg-replica now refuses the temp role(s) of a lease whose revocation is pending or irrevocable. Names the roles, the sessions terminated and the over-deny. |
| `pg_deny_descriptor_rejected` | A file in the descriptor volume failed validation (bug or compromised reconciler). |
| `pg_deny_watcher_failed` | The watcher was restarted, its supervisor stopped, the descriptor directory is unreadable, or a rewrite or reload failed. |
| `pg_server_process_crashed` | The postmaster saw a child die abnormally and restarted every session. |

The PostgreSQL superuser-login exception also covers the deny-list watcher (local socket and `application_name=pg-deny-watcher`, which a local superuser could fake).

- `superuser_login` is noisy: about 600 alerts in one full test cycle, because every `docker exec` by an operator logs in as a superuser. This is correct behaviour. It is the "`docker exec` bypass" alert from 7.4.
- Nothing sends notifications yet.
- Not built: bulk-export detection, break-glass reads.

---

## 5. Configuration for workstream C (one app, one PostgreSQL + one MariaDB)

CLI is `bao`. Names (`app1`, `debug_ro`, hosts) are placeholders.

### 5.1 One-time setup in each database

PostgreSQL 16 or later, on the **primary**, as superuser:

```sql
REVOKE CONNECT, TEMPORARY ON DATABASE app1 FROM PUBLIC;
REVOKE CONNECT ON DATABASE postgres FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT CONNECT ON DATABASE app1 TO app1_runtime, app1_migrator;

-- masked surface: developers see only schema "debug"
CREATE ROLE view_owner NOLOGIN;
GRANT USAGE ON SCHEMA public TO view_owner;
GRANT SELECT ON public.customers, public.orders TO view_owner;   -- explicit allow-list
CREATE SCHEMA debug AUTHORIZATION view_owner;
SET ROLE view_owner;
CREATE VIEW debug.customers WITH (security_barrier) AS
  SELECT id,
         left(email, 2) || '***'     AS email,
         left(full_name, 1) || '***' AS full_name,
         created_at
  FROM public.customers;
CREATE VIEW debug.orders AS
  SELECT id, customer_id, total, created_at FROM public.orders;
RESET ROLE;

CREATE ROLE debug_ro NOLOGIN;
GRANT CONNECT ON DATABASE app1 TO debug_ro;
GRANT USAGE ON SCHEMA debug TO debug_ro;
GRANT SELECT ON ALL TABLES IN SCHEMA debug TO debug_ro;
ALTER DEFAULT PRIVILEGES FOR ROLE view_owner IN SCHEMA debug GRANT SELECT ON TABLES TO debug_ro;

CREATE ROLE bao_admin LOGIN CREATEROLE PASSWORD '<initial>';
GRANT debug_ro TO bao_admin WITH ADMIN TRUE, INHERIT FALSE, SET FALSE;   -- can grant the role, cannot read the views itself
GRANT pg_signal_backend TO bao_admin;            -- to terminate temp sessions
GRANT CONNECT ON DATABASE app1 TO bao_admin;     -- needed because CONNECT is revoked from PUBLIC

CREATE ROLE session_sweeper LOGIN PASSWORD '<sweeper-password>' CONNECTION LIMIT 2;
GRANT pg_signal_backend TO session_sweeper;
GRANT CONNECT ON DATABASE app1 TO session_sweeper;   -- CONNECT is revoked from PUBLIC
ALTER ROLE session_sweeper SET statement_timeout = '10s';

-- replication (primary)
CREATE ROLE replicator LOGIN REPLICATION NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS
  CONNECTION LIMIT 3 PASSWORD '<pw>';                       -- pg_basebackup -X stream uses 2
SELECT pg_create_physical_replication_slot('pg_replica');   -- and on the primary: max_slot_wal_keep_size = 1GB
```

Create both sweeper accounts on the primary so they replicate.

Why it looks like this:
- `debug_ro` has **no grant on base tables**, only on views in schema `debug`.
- There is **no** `ALTER DEFAULT PRIVILEGES` on schema `public`. New tables stay invisible to developers until a view is reviewed and added. The design fails closed.
- Views use explicit column lists, not `SELECT *`. Columns added later stay hidden until someone reviews them and recreates the view, and every exposed column is named in the review.
- `bao_admin` can grant `debug_ro` but, with `INHERIT FALSE, SET FALSE`, cannot read the views itself. It is still a member for `pg_hba.conf` `+debug_ro` matching, so its line stays first.
- Views run with the **owner's** privileges (`view_owner`), so `debug_ro` can read the view without reading the table.
- PostgreSQL 16+ is required. Before 16, `CREATEROLE` is close to superuser. From 16, a `CREATEROLE` role can only manage roles it created or holds `ADMIN OPTION` on.

`pg_hba.conf` on the **primary**. First match wins. `bao_admin` is itself a member of `debug_ro`, so its line must come first.

```
# primary
local   all          postgres                       peer
hostssl app1         bao_admin      <openbao-ip>/32 scram-sha-256
host    all          +debug_ro      all             reject
hostssl app1         app1_runtime   <app-subnet>    scram-sha-256
hostssl app1         app1_migrator  <pipeline-net>  scram-sha-256
hostssl replication  replicator     <replica-ip>/32 scram-sha-256
host    replication  all            all             reject
host    all          all            all             reject
```

The replication line is needed for streaming replication. The keyword `all` in the database column does not match replication connections, so the final `reject` does not cover them. Keep the explicit line narrow and add the explicit `host replication all all reject` line.

`pg_hba.conf` on the **replica**:

```
# replica
local   all          postgres                         peer
host    all          @/var/lib/postgresql/pg-deny/denied_roles  all  reject
host    all          bao_admin        all             reject
hostssl app1         +debug_ro        <access-subnet> scram-sha-256
hostssl app1         session_sweeper  <sweeper-ip>/32 scram-sha-256
host    replication  all              all             reject
host    all          all              all             reject
```

Line 2 is the replica-side deny list (5.4). Its include file is written only by the watcher inside the replica (owner `postgres`, 0600, not on any shared volume) and always starts with the sentinel `/^$`. Measured on PostgreSQL 17: an `@file` with no token is a parse error (the server does not start; a reload keeps the old rules), regular expressions work inside it, and `all`, `+group`, `@file` and comma lists inside it are interpreted, and quoting does not neutralise a `/regex`. The file therefore contains only `/^v-...$` patterns built from validated input. The replica image now includes tini (MIT licence).

The `bao_admin` ordering trap is real. `bao_admin` is a member of `debug_ro` (ADMIN only, INHERIT and SET false), so it matches `+debug_ro`. On the primary, the `bao_admin` allow line must come before `host all +debug_ro all reject`. On the replica, an explicit `host all bao_admin all reject` line comes before the allow lines (after the deny-list line, 5.4). The order above was verified working; the reversed order was not run.

Temp users can log in on the replica only. The same credentials are rejected on the primary. The primary is not on the `access` network, and it refuses them at authentication from the app and replication networks.

Replica settings (PostgreSQL):

```
primary_conninfo = 'host=pg-primary port=5432 user=replicator application_name=pg-replica sslmode=verify-full sslrootcert=<ca.crt> passfile=<passfile>'
primary_slot_name = 'pg_replica'
max_standby_streaming_delay = 30s
hot_standby_feedback = off
```

- Do not use `pg_basebackup -R`. It writes the password into `postgresql.auto.conf`. Use a passfile built from the secret at start.
- A hot standby refuses writes, `CREATE TABLE` and `CREATE TEMP TABLE` with "read-only transaction" before any privilege check. This held even for probe accounts with `INSERT` and `UPDATE` grants and for the superuser.

MariaDB, on the **primary**, as root:

```sql
CREATE DATABASE app1_masked;
CREATE USER 'view_owner'@'localhost' ACCOUNT LOCK;
GRANT SELECT ON app1.customers TO 'view_owner'@'localhost';
GRANT SELECT ON app1.orders TO 'view_owner'@'localhost';
CREATE DEFINER = 'view_owner'@'localhost' SQL SECURITY DEFINER VIEW app1_masked.customers AS
  SELECT id,
         CONCAT(LEFT(email, 2), '***')     AS email,
         CONCAT(LEFT(full_name, 1), '***') AS full_name,
         created_at
  FROM app1.customers;
CREATE DEFINER = 'view_owner'@'localhost' SQL SECURITY DEFINER VIEW app1_masked.orders AS
  SELECT id, customer_id, total, created_at FROM app1.orders;

-- passwords: never IDENTIFIED BY (clear text in the binlog, see 4.E)
-- bao_admin (lab probe roles only; temp users are created on the replica)
CREATE USER 'bao_admin'@'<openbao-ip>' REQUIRE SSL ACCOUNT LOCK;
GRANT CREATE USER, CONNECTION ADMIN ON *.* TO 'bao_admin'@'<openbao-ip>';
GRANT SELECT ON app1_masked.* TO 'bao_admin'@'<openbao-ip>' WITH GRANT OPTION;
SET PASSWORD FOR 'bao_admin'@'<openbao-ip>' = PASSWORD('<initial>');
ALTER USER 'bao_admin'@'<openbao-ip>' ACCOUNT UNLOCK;

-- sweeper (replicates; see 5.4)
CREATE USER 'session_sweeper'@'<sweeper-ip>' REQUIRE SSL WITH MAX_USER_CONNECTIONS 2 ACCOUNT LOCK;
GRANT PROCESS, CONNECTION ADMIN ON *.* TO 'session_sweeper'@'<sweeper-ip>';
GRANT SELECT (User) ON mysql.user TO 'session_sweeper'@'<sweeper-ip>';
SET PASSWORD FOR 'session_sweeper'@'<sweeper-ip>' = PASSWORD('<pw>');
ALTER USER 'session_sweeper'@'<sweeper-ip>' ACCOUNT UNLOCK;

-- replication account
CREATE USER 'replicator'@'<replica-ip>' REQUIRE SSL ACCOUNT LOCK;
GRANT REPLICATION SLAVE ON *.* TO 'replicator'@'<replica-ip>';
SET PASSWORD FOR 'replicator'@'<replica-ip>' = PASSWORD('<pw>');
ALTER USER 'replicator'@'<replica-ip>' ACCOUNT UNLOCK;
```

MariaDB, on the **replica**, as root, in a session with `SET SESSION sql_log_bin = 0`. The account `bao_replica_admin` is created **locally on the replica**, so it never exists on the primary and is never binlogged. A host mask could not separate the two servers, because OpenBao reaches both from the same address.

```sql
-- on the replica, as root, in a session with SET SESSION sql_log_bin = 0
CREATE USER IF NOT EXISTS 'bao_replica_admin'@'<openbao-ip on bao-replica>' REQUIRE SSL ACCOUNT LOCK;
GRANT CREATE USER, READ ONLY ADMIN, BINLOG ADMIN, CONNECTION ADMIN ON *.* TO 'bao_replica_admin'@'<openbao-ip>';
GRANT SELECT ON app1_masked.* TO 'bao_replica_admin'@'<openbao-ip>' WITH GRANT OPTION;
SET PASSWORD FOR 'bao_replica_admin'@'<openbao-ip>' = PASSWORD('<one-time initial password>');
ALTER USER 'bao_replica_admin'@'<openbao-ip>' ACCOUNT UNLOCK;
-- then configure OpenBao and rotate-root at once (5.2)
```

Proven: `bao_replica_admin` cannot log in to the primary and has no rows or grants there. It is refused on the replica from the developer network.

Each privilege was measured by removing it:
- Without `CREATE USER`, creating and dropping users is refused.
- Without `READ ONLY ADMIN`, every write is refused because of `read_only`, including its own password change.
- Without `BINLOG ADMIN`, `sql_log_bin` cannot be set. `SUPER` is not a substitute in MariaDB 11.8.
- Without `CONNECTION ADMIN`, `KILL USER` returns no error and kills nothing.
- Without `SELECT ... WITH GRANT OPTION` on `app1_masked.*`, the GRANT is refused.

MariaDB replica:

```sql
CHANGE MASTER TO MASTER_HOST='maria-primary', MASTER_PORT=3306, MASTER_USER='replicator', MASTER_PASSWORD='<pw>',
  MASTER_SSL=1, MASTER_SSL_CA='<ca.crt>', MASTER_SSL_VERIFY_SERVER_CERT=1,
  MASTER_USE_GTID=slave_pos, MASTER_CONNECT_RETRY=10;
```

The replica runs with `read_only=ON`. Its `read_only` error also precedes privilege errors. Accounts with `READ ONLY ADMIN` bypass `read_only`. It is included in `ALL PRIVILEGES`, so root bypasses it too. Keep root socket-only on replicas. `bao_replica_admin` holds `READ ONLY ADMIN` on purpose (see above).

The replica has its own binary log: `log_bin`, `log_slave_updates = ON`, `binlog_format = ROW`, 7-day expiry.

The replica also runs with `--init-file` (the startup purge of all local `v-` users and the definition of the expiry-backstop event, both with `sql_log_bin = 0`), `--event-scheduler=ON` and `--secure-file-priv` pointing at its backstop log directory (5.4).

**Seeding a MariaDB replica.** Used in the prototype:

- `mariadb-dump --all-databases --single-transaction --gtid --master-data=2 --routines --events --triggers --hex-blob --flush-privileges`, over verified TLS.
- Load the dump on the replica, set `gtid_slave_pos` from the dump header, then run `CHANGE MASTER`.
- Verified: the account list on the replica equals the primary's, and `gtid_slave_pos` equals the primary's `gtid_binlog_pos`.
- Load the dump with `sql_log_bin = 0` and with `server_audit_logging` switched OFF for the load only, in the image's init server (no network), then ON (4.E). The replica's audit log and the store then hold no `INSERT INTO global_priv` and no password hashes.
- The dump contains password hashes. Delete it after loading.
- The dump overwrites the replica's own local healthcheck accounts. Re-create them after the load.
- In the prototype the `replicator` account was given dump privileges (`SELECT, SHOW VIEW, TRIGGER, EVENT, LOCK TABLES, RELOAD, BINLOG MONITOR`). This is not minimised. For production, seed with a separate DBA account or `mariadb-backup`, and keep `replicator` at `REPLICATION SLAVE` only.

Why it looks like this:
- **No role is used on MariaDB.** The earlier draft used `SET DEFAULT ROLE ... FOR`, which needs write access to the `mysql` database and would have failed. Granting `UPDATE ON mysql.*` to fix it would let `bao_admin` edit its own privileges.
- Direct grants on the masked database avoid this. `bao_admin` can pass on `SELECT ON app1_masked.*` and nothing else.
- **Warning:** global `CREATE USER` lets `bao_admin` alter or drop **any** account on the primary, and `bao_replica_admin` any account on the replica. OpenBao compromise equals database account compromise. Restrict their hosts to the OpenBao address.
- A locked account as view definer works (verified). `view_owner` gets `SELECT` on the specific tables only, not `app1.*`.
- MariaDB has no `pg_hba.conf` equivalent. Temp users are created on the replica only, so they never exist on the primary. Their host mask and network separation (the primary is not on the `access` network) are a second layer.
- Temp users are created as `'{{name}}'@'<access-subnet mask>'` (for example `'10.81.5.0/255.255.255.0'`). The primary is not on the access network, so such an account can never match a connection to it.

### 5.2 Connect OpenBao to the databases

```bash
bao secrets enable database

bao write database/config/app1-pg \
  plugin_name=postgresql-database-plugin \
  connection_url="postgresql://{{username}}:{{password}}@pg-primary:5432/app1?sslmode=verify-full&sslrootcert=/bao/tls/db-ca.pem" \
  username=bao_admin password='<initial>' \
  password_authentication=scram-sha-256 \
  allowed_roles="app1-pg-ro,app1-pg-rw" \
  username_template='{{ printf "v-%s-%s-%s-%s" (.DisplayName | truncate 30) (.RoleName | truncate 12) (unix_time) (random 4) | truncate 63 }}'

bao write database/config/app1-maria \
  plugin_name=mysql-database-plugin \
  connection_url="{{username}}:{{password}}@tcp(maria-primary:3306)/" \
  username=bao_admin password='<initial>' \
  tls_ca=@/bao/tls/db-ca.pem tls_server_name=maria-primary \
  allowed_roles=<lab probe roles only> \
  username_template='{{ printf "v-%s-%s-%s-%s" (.DisplayName | truncate 40) (.RoleName | truncate 16) (unix_time) (random 4) | truncate 80 }}' \
  root_rotation_statements="SET PASSWORD = PASSWORD('{{password}}')"

# MariaDB temp users: on the replica, never binlogged
bao write database/config/app1-maria-replica \
  plugin_name=mysql-database-plugin \
  connection_url='{{username}}:{{password}}@tcp(<replica-admin-host>:3306)/?sql_log_bin=0' \
  tls_ca=@ca.crt tls_server_name=<replica-cert-name> \
  username=bao_replica_admin password='<one-time initial password>' \
  allowed_roles=app1-maria-ro \
  root_rotation_statements="SET @sql_log_bin_must_be_0 = (SELECT 1 UNION ALL SELECT 1 FROM DUAL WHERE @@session.sql_log_bin <> 0); SET PASSWORD = PASSWORD('{{password}}')"

# After this, only OpenBao knows the admin passwords
bao write -force database/rotate-root/app1-pg
bao write -force database/rotate-root/app1-maria
bao write -force database/rotate-root/app1-maria-replica
```

Notes:
- MariaDB uses the MySQL plugin.
- `sslrootcert=` in the PostgreSQL URL is resolved on the OpenBao server, so that CA file must be in the OpenBao container. `tls_ca=@...` for MariaDB is different: the CLI reads the file on the machine where `bao write` runs and stores the content in the configuration.
- Re-running `bao write database/config/<name>` without a `password` keeps the rotated password. A setup script must not send the initial password again after `rotate-root`.
- `username_template` is a parameter of `database/config`, not of the role.
- **Why a custom template:** the defaults keep only 8 (PostgreSQL) or 10 (MySQL) characters of the display name. The display name starts with the `oidc-` mount prefix, so the person is not identifiable. The replica's expiry backstop relies on the embedded unix time, parsed with the end-anchored regex `(?<=-)[0-9]{10}(?=-[^-]+$)` (5.4).
- The PostgreSQL parts add up to at most 61 characters, so the final `truncate 63` never cuts the timestamp. The MariaDB name is at most 2+40+1+16+1+10+1+4 = 75 characters, so `truncate 80` never cuts the timestamp or the suffix. The 80-character MariaDB user name limit: to test against the production version.
- `root_rotation_statements` is needed for MariaDB because the default rotation statement assumes host `'%'`. It must also not use `ALTER USER ... IDENTIFIED BY`: that writes the new password to the binary log in clear text. The test recovered the new `bao_admin` password from the binlog and logged in with it. `SET PASSWORD = PASSWORD('{{password}}')` changes the connecting user's own password, and the binlog then holds only the hash (tested). The earlier leaked password no longer works.
- **`sql_log_bin=0` goes in the connection URL, not in the statements.** OpenBao's MySQL plugin runs each statement list inside a transaction, and MariaDB refuses `SET SESSION sql_log_bin` there (error 1694). `SET STATEMENT sql_log_bin=0 FOR ...` fails the same way. The Go driver sends `SET sql_log_bin=0` on every new pooled connection.
- **Every statement list begins with a guard** that fails closed if binary logging is on: `SET @sql_log_bin_must_be_0 = (SELECT 1 UNION ALL SELECT 1 FROM DUAL WHERE @@session.sql_log_bin <> 0);`. Without the URL parameter, the guard fails with error 1242 and no user is created (tested). Without guard and parameter (measured once), the temp user's `CREATE USER`, password included, went into the replica's own binlog with a replica GTID, and the next primary write stopped replication under `gtid_strict_mode`.
- The `app1-maria-replica` rotation uses the same guard and `SET PASSWORD`. The `bao_admin` connection to the MariaDB primary stays only for lab probe roles.- `password_authentication=scram-sha-256` is a documented option of the PostgreSQL plugin. OpenBao then sends a hash, not the cleartext password. It works with the 5.3 statements (verified). It keeps the password out of the PostgreSQL logs when statement logging is on; with `log_statement = none` and pgAudit redaction it is a second layer (see 4.E).

**Consequences of rotate-root:** nobody knows the `bao_admin` password afterwards. If OpenBao storage is lost, a DBA must reset `bao_admin` through the local superuser and reconfigure the connection.

**Lease reconciler AppRole.** The reconciler (5.4) logs in to OpenBao with its own AppRole. The policy `lease-reconciler` is in 5.5.

```bash
bao auth enable approle
bao policy write lease-reconciler lease-reconciler.hcl
bao write auth/approle/role/lease-reconciler token_policies=lease-reconciler token_no_default_policy=true token_type=batch token_ttl=300 token_max_ttl=300 token_bound_cidrs=<reconciler>/32 secret_id_bound_cidrs=<reconciler>/32
```

The reconciler reaches OpenBao only over its own internal network (5.4).

### 5.3 Temporary-access roles

```bash
bao write database/roles/app1-pg-ro db_name=app1-pg \
  default_ttl=1h max_ttl=4h \
  creation_statements="CREATE ROLE \"{{name}}\" LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}' CONNECTION LIMIT 2; GRANT debug_ro TO \"{{name}}\"; ALTER ROLE \"{{name}}\" SET statement_timeout = '60s'; ALTER ROLE \"{{name}}\" SET idle_session_timeout = '15min';" \
  revocation_statements="SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = '{{name}}'; DROP ROLE IF EXISTS \"{{name}}\";"

bao write database/roles/app1-maria-ro db_name=app1-maria-replica \
  default_ttl=1h max_ttl=4h \
  creation_statements="SET @sql_log_bin_must_be_0 = (SELECT 1 UNION ALL SELECT 1 FROM DUAL WHERE @@session.sql_log_bin <> 0); CREATE USER '{{name}}'@'<access-subnet mask>' IDENTIFIED BY '{{password}}' REQUIRE SSL WITH MAX_USER_CONNECTIONS 2 MAX_STATEMENT_TIME 60 PASSWORD EXPIRE INTERVAL 1 DAY; GRANT SELECT ON app1_masked.* TO '{{name}}'@'<access-subnet mask>';" \
  revocation_statements="SET @sql_log_bin_must_be_0 = (SELECT 1 UNION ALL SELECT 1 FROM DUAL WHERE @@session.sql_log_bin <> 0); KILL USER '{{name}}'; DROP USER IF EXISTS '{{name}}'@'<access-subnet mask>';"
```

The MariaDB role runs on the replica connection, so its `IDENTIFIED BY '{{password}}'` never reaches a binary log. The rule against `IDENTIFIED BY` (4.E) is for servers whose statements are binlogged.

Notes:
- `default_ttl=1h`, `max_ttl=4h`.
- `KILL USER` needs `CONNECTION ADMIN` and returns no error when the user has no connections. It is verified to kill open sessions through the plugin.
- The MariaDB statements run on the replica with `sql_log_bin=0` from the connection URL (5.2). The guard at the start of each list makes them fail closed if binary logging is on.
- Do **not** change it to the `'{{name}}'@'<host mask>'` form. That form silently kills nothing, because it is compared with the client's real host, not with the account's host mask.
- `bao lease renew -increment=20s <lease-id>` shortens a lease and is allowed by the default policy. Useful for expiry tests.
- `statement_timeout = '60s'` displays as `1min` in a session.
- Timeouts set with `ALTER ROLE ... SET` are defaults. The user can override them with `SET`. They are a guard rail, not a control.
- Do not use `DO` blocks in statements: the plugin splits statements on semicolons.
- The termination in the PostgreSQL revocation statement runs on the primary only. Temp users cannot log in there, so it matters only as defence in depth. See 5.4 for the replica.
- The `app1-pg-rw` break-glass role follows the same pattern with `default_ttl=30m max_ttl=30m`, a separate write role in place of `debug_ro`, and its own `pg_hba.conf` line on the primary. Its details are for phase 6.

### 5.4 Sessions outlive revocation

This is the most important correction to the first draft.

Facts:
- Dropping a role or user does **not** disconnect its open sessions, on either engine.
- PostgreSQL `VALID UNTIL` is checked only at login.
- Termination issued on the primary does not reach the replica. MariaDB `KILL` is not replicated.

Measured on the PostgreSQL replica with the sweeper stopped:
- `DROP ROLE` replayed on the standby 2 s after the revoke, even with a session of that role open. Replay is not blocked. The session stayed open over 20 s with `usename` NULL.
- PostgreSQL immediately denies the orphaned session ("permission denied for schema", then "invalid role OID").

On MariaDB the revocation statements run on the replica itself, so there is no replication step. `KILL USER` ends open sessions about 0.8 s after `bao lease revoke`, with or without the sweeper. An **orphaned MariaDB session keeps its privileges** after its account is dropped without a kill. It still read the masked view. The sweeper is therefore defence in depth on MariaDB, for accounts that vanish without a kill (tested).

On PostgreSQL the exposure window is up to one sweep interval plus replication lag. Replication lag and replicated revocation now apply to PostgreSQL only.

Therefore each **replica** runs a sweeper every minute (a small cron container on the `access` network). The lab used a 10 s interval.

**PostgreSQL sweeper.** Run as `session_sweeper` on the replica. `pg_signal_backend` alone is enough. Without `pg_read_all_stats`, `pg_stat_activity` shows `backend_type`, `backend_start`, `state`, `query` and `client_addr` as NULL for other roles' sessions. Only `pid` and `usesysid` are visible, so any filter on the other columns silently matches nothing. Granting `pg_read_all_stats` would also expose every session's query text. The sweeper is therefore written to need only `pid` and `usesysid`. It lists candidates:

```sql
SELECT a.pid, a.usesysid, coalesce(r.rolname, '-'),
       CASE WHEN r.oid IS NULL THEN 'role-dropped' ELSE 'valid-until-passed' END
FROM pg_stat_activity a LEFT JOIN pg_roles r ON r.oid = a.usesysid
WHERE a.pid <> pg_backend_pid()
  AND a.usesysid IS NOT NULL
  AND (r.oid IS NULL OR (r.rolname LIKE 'v-%' AND r.rolvaliduntil < now()));
-- then, per pid:
SELECT pg_terminate_backend(a.pid) FROM pg_stat_activity a LEFT JOIN pg_roles r ON r.oid = a.usesysid
WHERE a.pid = <pid> AND <same condition>;
```

- After a replicated `DROP ROLE`, an open session's `usename` is NULL. It is found by its `usesysid` missing from `pg_roles`.
- `usesysid IS NOT NULL` excludes walreceiver, startup and other auxiliary processes.
- A `backend_start` age clause is not needed. Renewing a lease updates `VALID UNTIL`, and `max_ttl` caps it.
- `pg_has_role(x, 'debug_ro', 'member')` is true for `bao_admin` (it holds the role WITH ADMIN). This is a trap for any sweeper that filters by membership.

**MariaDB sweeper**, on the replica. The account is created on the primary and replicates (see 5.1). It is defence in depth (see above). Privileges, measured with probe accounts:
- `PROCESS` is needed. Without it, PROCESSLIST shows only the account's own connections.
- `CONNECTION ADMIN` is needed. Without it, `KILL` fails with "You are not owner of thread".
- `SELECT` on `mysql.user` is needed, but a column grant on `User` is enough. The sweeper cannot read `authentication_string` (tested). A table-wide grant would expose every password hash.

It kills every connection whose user starts with `v-` and no longer exists in `mysql.user`. The query works unchanged:

```sql
SELECT CONCAT('KILL CONNECTION ', p.ID, ';')
FROM information_schema.PROCESSLIST p
WHERE p.USER LIKE 'v-%'
  AND NOT EXISTS (SELECT 1 FROM mysql.user u WHERE u.User = p.USER);
-- the cron script pipes the generated statements back into the mariadb client
```

MariaDB has no `VALID UNTIL`, so the MariaDB sweeper only handles dropped accounts.

**Measurements** (lab sweeper interval 10 s; the production proposal stays 1 minute). Ranges across runs:

| What | PostgreSQL | MariaDB |
|---|---|---|
| New credentials working on the replica | 0.2 to 0.9 s (replication) | under 2 s (created on the replica) |
| Revoke to user dropped on the replica | 2 s | no replication step |
| `bao lease revoke` to replica session gone | 1.4 to 10.5 s | about 0.8 s (`KILL USER`, with or without the sweeper) |
| TTL expiry to replica session gone | 2.7 to 13.5 s | about 0.1 s |
| Sweeper started to orphaned session gone | 2.1 to 2.2 s | 2.3 to 2.5 s |

The PostgreSQL TTL figure can exceed the interval. It includes OpenBao's expiry processing, and `VALID UNTIL` lands about 5 s after the lease's expiry time.

#### Revocation when the database is unreachable (both engines closed)

MariaDB temp users live only on the replica, so OpenBao must reach it to revoke.
- If the replica is down when a lease is revoked or expires, OpenBao queues the revocation. OpenBao retries with growing, jittered delays and logs each `next_attempt`. Measured examples: 26 s, 22 s, 43 s, 3m12 s for one lease; 29 s, 35 s, 1m41 s for another. After 6 attempts the lease becomes irrevocable (542.8 s in the final run; 10 to 11 minutes in earlier runs).
- Before the backstops, logins worked in that gap (31 to 57 s). Now the startup purge drops every local `v-` user from the `init_file`, before any connection is answered. Measured: with about 2,000 attempts at about 25 ms, no attempt was answered before the purge completed. The listening socket exists while the `init_file` runs, so one attempt waited in the listen backlog and was answered 0.05 to 0.07 s after the purge. The first session of any account ran about 0.1 s after the purge by the server's clock. The revoked user and the still-valid user never logged in.
- After an outage longer than about 11 minutes, the lease is irrevocable. The purge drops the user at the restart, and the reconciler revokes the irrevocable lease. Measured: detected within one pass, revoked 20 s after the replica was healthy, with 16 failed attempts before that.
- Recovery: `bao read sys/leases type=irrevocable`, then `bao lease revoke -sync <id>` (tested; automated by the reconciler).
- `bao lease revoke -sync` during the outage fails and is not retried. The lease keeps its TTL.
- The sweeper cannot close the gap, because it has no OpenBao state.

Built (lab), four layers (1 to 3 for MariaDB, 3 and 4 for PostgreSQL):
1. **Startup purge.** `maria-replica` runs an `--init-file`, generated by a wrapper entrypoint from a template. It starts with `SET SESSION sql_log_bin=0`, drops every `'v-%'` user from `mysql.global_priv` before the server answers any connection, and writes a line with `SELECT ... INTO OUTFILE` into a `--secure-file-priv` directory on its audit volume (`/var/log/mariadb-audit/backstop`, mode 2750).
2. **Expiry backstop.** A replica-local event `replica_local.revocation_backstop` runs `EVERY 15 s` in the lab (proposal: 300 s with a 900 s margin in production), with `sql_log_bin=0`. Its definer is `'revocation_backstop'@'localhost'` (locked, local, no password). It parses the unix time in the user name with `(?<=-)[0-9]{10}(?=-[^-]+$)`. For `v-` users older than `max_ttl` (14400 s) plus the margin (lab 300 s), it does `ALTER USER ... ACCOUNT LOCK`, `KILL USER`, `DROP USER`, then writes a log line. Definer privileges: `CREATE USER`, `READ ONLY ADMIN`, `BINLOG ADMIN`, `CONNECTION ADMIN`, `FILE` (limited by `--secure-file-priv`), `SELECT (User, Host) ON mysql.global_priv`, `EVENT ON replica_local.*`. Each was measured by removal: without `CONNECTION ADMIN` the session survives; without `FILE` the drop happens but the log line and the alert are lost. Events arriving from the primary are created `SLAVESIDE_DISABLED` (tested). **Warning:** `ALTER EVENT` without a `DEFINER` clause makes the user running it (root) the definer (measured). A replica restart re-creates the event from the `init_file`. Setup refuses to finish unless the event is `ENABLED` with the correct definer.
3. **Lease reconciler.** A container (`openbao/openbao:2.7.2` image, user 100:1000, `read_only`, `cap_drop ALL`, 64m, `no-new-privileges`) on its own internal network `bao-reconciler` (10.81.10.0/24) at 10.81.10.20; OpenBao joins it at 10.81.10.10. A shell loop runs every 15 s in the lab (60 s proposed). It logs in with AppRole (5.2; policy in 5.5), lists irrevocable leases (`GET sys/leases?type=irrevocable`) and revokes those under `database/creds/` (`sync=true`). It also lists `database/creds` leases, looks up the TTL, and re-revokes leases with `ttl<=0` seen on two consecutive passes (pending revocations), with a per-lease backoff (at most 2 passes in the lab). It logs `action=start`, `ready`, `error`, `recovered`, `irrevocable-found`, `revoke-irrevocable` and `revoke-retried`, each with an outcome. It now also writes the PostgreSQL deny descriptors (layer 4).

Measured:
- The purge completed 3.36 s and 2.84 s after `docker compose start maria-replica`.
- The expiry backstop dropped a backdated user 8.0 s and 8.1 s after the event was enabled, and killed its session 7.4 s and 7.5 s after. Nothing was binlogged and the alert shipped.
- The reconciler completed a pending MariaDB revocation 8.4 s and 26.7 s after `maria-replica` was healthy, and a PostgreSQL one 9.0 s and 27.3 s after `pg-primary` was healthy. OpenBao's own next retries were due 108 to 227 s after the start.

4. **PostgreSQL replica deny list (built, lab).** While the primary is down, the standby cannot drop a revoked role.
   - **Reconciler.** For every lease of a listed PostgreSQL role (`PG_DENY_ROLES`) with TTL <= 0 (from the first pass that sees it) or irrevocable, the reconciler writes `<role>.<lease suffix>.deny` containing exactly `v1 <role> <issue_time unix>` into a volume. It writes a dot-file and renames it, and needs no new permission: `issue_time` comes from `sys/leases/lookup`. Only the reconciler mounts the volume read-write; the replica mounts it read-only; they share no network. The reconciler removes the file once OpenBao answers "invalid lease", never on another error. MariaDB leases get none.
   - **Watcher.** It runs inside the replica as `postgres`, started by the entrypoint under `tini -s` (child subreaper). The server remains PID 1. PostgreSQL 17 treats any unknown child of the postmaster that dies by a signal or with an exit code other than 0 or 1 as a crashed backend and restarts every session (measured), so nothing the watcher forks may be reaped by the postmaster.
   - **Validation.** Accepted: regular files only, a strict name pattern, at most 129 bytes read with nofollow/nonblock, exactly one line, a role equal to the file name's and on an allowlist, a 10-digit time not in the future. Anything else is logged and alerted (content never logged) and ignored.
   - **Patterns.** Each valid descriptor becomes `/^v-.+-<role, 12 chars>-(<t-3>..<t>)-[A-Za-z0-9]{4}$`. The username's unix time is taken just before the lease is created: measured 0 s in 29 of 30 leases, 1 s once.
   - **Apply.** The watcher writes the include file, checks it with `pg_hba_file_rules`, reloads with `pg_ctl reload` (which works on a standby), and terminates matching sessions with `pg_terminate_backend` over the local socket.
   - **Restarts.** The entrypoint writes the file before the server starts, so a restart has no login window.
   - **Release.** When the descriptor is gone, an entry is released once no role matches it. If a role still matches (another role of the same seconds), it is released 60 s later and only while the standby is streaming.
   - **Fail-safe.** The server always starts (the sentinel is written even if the step fails); a missing descriptor directory is logged and alerted; the supervisor restarts a dead watcher and alerts; a SIGTERM to the supervisor is alerted and the current file stays in effect (the healthcheck turns unhealthy after 30 s without a heartbeat); SIGKILL of the supervisor or tini crash-restarts every replica session (alerted).
   - **Measured** (four runs, 180 s outages, lab reconciler interval 15 s): revoked role refused 3.8 to 12.7 s after the revoke and never again during the outage (0 successes in 321 to 332 attempts); its open session ended 3.6 to 12.5 s after the revoke. A still-valid role of another second was unaffected (31/31, 34/34 logins, session kept); a still-valid role of the same second was refused (over-deny, logged as `matched=2`). A replica restart during the outage wrote the deny list about 0.5 s before the first accepted login: 0 revoked logins in 9 to 13 attempts. After the primary returned the reconciler completed the revocation 1.3 to 18.5 s after it was healthy (OpenBao's own retry was 102 to 217 s away); the role was dropped on the replica 9.6 to 26.9 s and the deny list was back to the sentinel 83 to 104 s after the start command. `kill -9` of the watcher: restarted in about 1 s. 23 malicious descriptors (quotes, newlines, `all`, `+group`, `@file`, `replicator`, `bao_admin`, `postgres`, path traversal, symlink, oversized, FIFO and others) were rejected with `pg_hba` unchanged.
   - **Formerly** (before the deny list): the revoked role logged in 10 of 10 times during a 150 s outage, bounded by `VALID UNTIL`.

Remaining proposals: a shorter PostgreSQL `default_ttl`; a runbook to promote the standby during long outages; a cross-host descriptor transport for replicas on other hosts.

**Stale-user detection.** A report-only detector logs `v-` accounts past their maximum lifetime. PostgreSQL is checked on the primary by `rolvaliduntil`; MariaDB is checked on the replica by account age. It does not drop them. It was built and tested in phase 3. This catches leases OpenBao could not revoke: after 6 failed attempts a lease becomes irrevocable and the DB user stays.

**Automatic cleanup.** MariaDB: done by the event above with a least-privilege definer, not as root. PostgreSQL: still report-only. The timestamp is parsed with a regular expression, not by splitting on `-`, because display names can contain hyphens.

MariaDB `PASSWORD EXPIRE INTERVAL 1 DAY` is only a coarse backstop: it works in whole days.

### 5.5 Who may request credentials

OIDC auth against Keycloak:

```bash
bao auth enable oidc

bao write auth/oidc/config \
  oidc_discovery_url="https://<keycloak>/realms/<realm>" \
  oidc_client_id="openbao" oidc_client_secret="<client-secret>" \
  default_role="dev"

bao write auth/oidc/role/dev \
  role_type=oidc \
  user_claim=preferred_username \
  groups_claim=groups \
  claim_mappings=preferred_username=username \
  allowed_redirect_uris="http://localhost:8250/oidc/callback" \
  allowed_redirect_uris="https://<bao>/ui/vault/auth/oidc/oidc/callback" \
  token_max_ttl=4h
```

- `localhost:8250` is the CLI callback; the second URI is for the web UI.
- Token max TTL 4h. Leases die with the token.
- `claim_mappings=preferred_username=username` puts the person in the auth metadata, so every audit entry names the person.
- A `jwt`-type role against Keycloak also needs `bound_audiences`.
- The client secret should come from a secret, not be pasted into commands. Keycloak realm import can substitute an environment placeholder.

Keycloak:
- Confidential client `openbao`.
- "Group Membership" mapper with claim name `groups` and "Full group path" OFF.
- Disable username editing in the realm. The username lands in DB user names and audit logs.
- Keycloak omits the `groups` claim entirely for a user with no groups, and OpenBao then refuses the login ("groups claim not found"). Give every user a realm default group, so people outside `app1-devs` can log in and simply get no access.

OpenBao groups. An external group holds only one alias, and a second alias silently replaces the first. With more than one auth mount, use one external group per auth mount, each with alias `app1-devs` on that mount's accessor, and make both members of an internal group `app1-devs` that carries the policy:

```bash
bao write identity/group name=app1-devs-oidc type=external
bao write identity/group-alias name=app1-devs mount_accessor=<oidc-accessor> canonical_id=<oidc-group-id>
bao write identity/group name=app1-devs-jwt type=external
bao write identity/group-alias name=app1-devs mount_accessor=<jwt-accessor> canonical_id=<jwt-group-id>
bao write identity/group/name/app1-devs type=internal policies=app1-debug \
  member_group_ids=<oidc-group-id>,<jwt-group-id>
```

With a single auth mount, one external group with `policies=app1-debug` and one alias works.

Policy:

```hcl
# policy: app1-debug.hcl
path "database/creds/app1-pg-ro"    { capabilities = ["read"] }
path "database/creds/app1-maria-ro" { capabilities = ["read"] }
```

Load it with `bao policy write app1-debug app1-debug.hcl`.

Lease reconciler policy (5.4):

```hcl
path "sys/leases/lookup/database/creds/*" {
  capabilities = ["list", "sudo"]
}
path "sys/leases/lookup" {
  capabilities = ["update"]
  allowed_parameters = {
    "lease_id" = ["database/creds/*"]
  }
}
path "sys/leases/revoke" {
  capabilities = ["update"]
  allowed_parameters = {
    "lease_id" = ["database/creds/*"]
    "sync"     = ["true"]
  }
}
path "sys/leases" {
  capabilities = ["read", "sudo"]
}
```

- It is granted only through the AppRole `lease-reconciler` (5.2): batch tokens of 300 s, no default policy, secret ID and token bound to the reconciler's /32 address.
- Each rule was measured by removal: each removal makes exactly its own call return 403. Both `sudo` capabilities are needed.
- Refused to the reconciler token (tested): `database/creds/*`, config, roles, `rotate-root`, policies, its own role ID, token create, `lookup-self`, renew, asynchronous revoke, `revoke-prefix`, `revoke-force`, the path form `sys/leases/revoke/<id>`, non-database leases, `sys/mounts` and cubbyhole. A login from another address on the same network was refused.
- Its credentials appear in no process listing, container configuration, `docker logs`, reconciler log, OpenBao audit log or store.
- Unchanged by the deny list: the issue time is part of the `sys/leases/lookup` response the policy already allows (the response is not filtered by policy; measured).

Audit device. Since OpenBao 2.3.2, `bao audit enable` over the API is refused unless `unsafe_allow_api_audit_creation = true`. Declare it in the server config instead:

```hcl
audit "file" "main" {
  options { file_path = "/var/log/bao/audit.log" }
}
```

### 5.6 Developer workflow

```bash
bao login -method=oidc
bao read database/creds/app1-pg-ro
# username  v-oidc-jane.doe-app1-pg-ro-1794787200-x8f2
# password  <generated>
# lease     1h

psql "host=<pg-replica> dbname=app1 user=v-oidc-jane.doe-app1-pg-ro-1794787200-x8f2 sslmode=verify-full"

# when finished
bao token revoke -self
```

- Connect to the **replica** through WireGuard.
- `bao token revoke -self` is allowed by the default policy. It revokes the token and all its leases.
- At TTL expiry OpenBao drops the user. On MariaDB `KILL USER` ends open sessions; on PostgreSQL the sweeper does.
- After a role is dropped, a new login fails at the final `pg_hba.conf` reject (the role is no longer a member of `debug_ro`), not with a password error.
- The display-name prefix follows the auth mount: `v-oidc-...` or `v-jwt-...`.

---

## 6. Gotchas and known limits

- **Keep temp users read-only.** A user that creates objects cannot be dropped cleanly, and the lease becomes hard to revoke.
- **OpenBao does not mask data.** Use views.
- **Approvals are not built into OpenBao.** That is the job of the portal (4.C). Removing a Keycloak group membership does not end OpenBao tokens that were already issued until the person logs in again or the token expires (measured, 4.C).
- **OpenBao is critical infrastructure and the trust root.** Plan unsealing, backups, and who holds unseal keys. Revoke the root token after setup.
- **PostgreSQL replica lag** delays both new credentials and revocation. An orphaned session keeps running until the sweeper kills it (5.4).
- **Revocation during a database outage.** MariaDB is covered by the startup purge, the expiry event and the lease reconciler (5.4). On PostgreSQL a role revoked while the primary is down is refused by the replica's deny list within one reconciler interval plus 2 s (5.4). The deny list has its own limits (7.5).
- **Hot-standby query cancellation.** Long debug queries on a PostgreSQL replica can be cancelled, or cause bloat with `hot_standby_feedback`. Keep statement timeouts.
- **Gateway and OpenBao integration is not automatic.** Warpgate has its own users and targets.
- **Warpgate does not record DB sessions.** It logs queries; replay is only for SSH, Kubernetes, RDP and VNC.
- **Audit log integrity:** ship OpenBao and database audit logs off-box to storage developers cannot modify.
- **The MariaDB binary log is not masked.** `server_audit` hides passwords, the binlog does not, for `IDENTIFIED BY` forms. Use hash-only forms and replica-only temp users (4.E).
- **Host access bypasses everything** (4.D). Detection, not prevention, covers host root.
- **Usernames include who requested them**, but the OpenBao audit log is the authoritative mapping. It needs the `username` tune from 4.E.
- **No mlock in OpenBao 2.7.** It rejects `disable_mlock` as an unknown field. The official image already runs as a non-root user and needed no change for `no-new-privileges`.

---

## 7. Prototype plan

Goal: prove all five workstreams end to end on disposable infrastructure: a Windows 10 Pro machine with 8 GB RAM. The stack is too large to run at once, so it is built in **phases**, with Compose profiles to start only what each phase needs.

### 7.1 Prerequisites

- Docker Desktop with the WSL2 backend. Docker Desktop was installed per-user; only the first-time WSL2 enablement needed an administrator.
- git.
- A native `bao.exe` on the host is **not** needed. The CLI OIDC callback works from a throwaway OpenBao container publishing `127.0.0.1:8250`, with `listenaddress=0.0.0.0` and `skip_browser=true`.
- Memory: the machine has 8 GB, with about 3 GB free when checked. Cap WSL2 at about 5 GB in `.wslconfig` and close other applications.

### 7.2 Phases

| Phase | Content | Done when | Status |
|---|---|---|---|
| 0 Baseline ("before") | Minimal .NET 10 API + PostgreSQL, minimal Laravel 13 API + MariaDB, Angular app behind nginx. Deliberately insecure: superuser credentials in env, published DB ports. Sample schema with a fake PII column. | Smoke tests pass. | Done 2026-11-16 (13 smoke tests). |
| 1 Workstreams A, B | Runtime and migrator roles, migrations as a separate step, Docker secrets, internal networks, no published ports, TLS. | Smoke tests still pass; Laravel container cannot reach PostgreSQL; DB ports unreachable from the host. | Done 2026-11-16 (13 smoke, 38 hardening). |
| 2 Workstream C, primaries only | OpenBao from a real config file (single-node integrated Raft storage, one Shamir key share for the lab, declarative audit device), not dev mode: dev mode loses rotated passwords and leases on restart. Keycloak realm with group `app1-devs` and two test users, one in the group, one not. Section 5 configuration. In this phase only, temp users were allowed on the primary (the no-replica fallback from 4.C). | Credentials issue; outsider denied. | Done 2026-11-16 (13 smoke, 38 hardening, 83 access checks). |
| 3 Replicas | PostgreSQL streaming replica (`pg_basebackup` bootstrap), MariaDB replica (`server_id`, binlog, GTID), `pg_hba.conf` split, sweepers. | Replica tests in 7.4 pass. | Done 2026-11-17. Streaming replica and GTID replica over verified TLS, `pg_hba.conf` split, primaries off the access network, sweepers, stale-user report (13 smoke, 38 hardening, 83 access, 93 replica checks). |
| 4 Workstream E | pgAudit (custom image) and `server_audit` on all servers, Fluent Bit to a volume only the log container mounts. | Audit tests in 7.4 pass. | Done 2026-11-17. pgAudit and `server_audit` on all four servers, Fluent Bit to an isolated store, lab alert rules, MariaDB binary-log password leak fixed by replica-only temp users and hash-only password statements. Revocation backstops: MariaDB startup purge and replica-local expiry event, a lease reconciler for both engines, and a PostgreSQL replica-side deny list (watcher inside pg-replica), with eight new alerts (13 smoke, 38 hardening, 84 access, 95 replica, 96 audit, 129 revocation checks (133 with the opt-in irrevocable-lease test), all passing on a from-scratch stack (re-run independently)). |
| 5 Debug telemetry (principle 1) | Traces and logs from the browser (Grafana Faro) and both APIs (OpenTelemetry) through Grafana Alloy to Loki and Tempo, read in Grafana with Keycloak sign-in. Redaction before storage. Configuration adapted from the existing `telemetries` repository. Separate from the audit pipeline. | One request gives one trace browser -> API -> SQL with correlated logs; sentinel personal data appears in no trace or log line; no telemetry container touches an audit volume; Grafana admits `app1-devs` only. | Done 2026-11-23 (27 phase 5 checks, 13 smoke; phase 4 suite on the phase 5 stack 94 of 96, see 7.5). Browser path also checked by hand in a real browser. |
| 6 Optional | Approval portal, Warpgate, break-glass role and alert. | Portal: requests with ticket and approver; no self-approval; the membership exists only while a grant is active; every step reaches the audit store; the service account cannot change anything else. | Portal done 2026-11-23 as an add-on to the phase 5 stack (`compose.phase6.yaml`, 83 phase 6 checks; see 4.C). Warpgate and break-glass not started. |

### 7.3 Windows notes

- Use named volumes, not NTFS bind mounts, for database data.
- Init scripts need LF line endings. Add `.gitattributes` with `eol=lf`. CRLF scripts fail silently.
- The Keycloak issuer hostname must be identical from the browser and from the OpenBao container. No hosts-file entry is needed: give Keycloak a `*.localhost` hostname (for example `keycloak.localhost`) with a matching Docker network alias and the same port inside and outside. Browsers resolve `*.localhost` to loopback by themselves. Windows PowerShell does not resolve `*.localhost`, so host scripts use `127.0.0.1`.
- The Windows host plays the developer. Containers that sit only on `internal` networks cannot publish ports, so the host cannot reach them directly. Either run the WireGuard client on the host against the WireGuard container, or, as a simpler first step, put OpenBao, Keycloak and the replicas on an extra non-internal `lab` network and publish their ports on `127.0.0.1` only. The primaries never get a published port.
- Script all configuration so the stack can be rebuilt from scratch.

### 7.4 Acceptance tests

All items below were proven in phases 0 to 5. None is unmet.

- [x] Credentials issue and work (on the primary in phase 2).
- [x] Credentials work on the replica.
- [x] The same credentials are **rejected** on the primary: unreachable from the access network, and refused at authentication from the app and replication networks.
- [x] `INSERT`, `UPDATE` and `DELETE` fail.
- [x] Base tables with PII are not readable; only the masked views are.
- [x] Temp users cannot connect to other databases or create objects.
- [x] A user outside `app1-devs` is denied.
- [x] The user disappears after TTL.
- [x] An **open** session is terminated on revoke. MariaDB: about 0.8 s on the replica (`KILL USER`).
- [x] On PostgreSQL, an open session is terminated within the sweeper interval plus 10 s of revoke or expiry on the replica.
- [x] Revoke while the replica is stopped, then start it: the user is gone and cannot log in. Met for MariaDB: startup purge; the order is proven by the poller; the lease is then completed by the reconciler (5.4).
- [x] The expiry backstop drops a backdated `v-` user within one interval, kills its session and binlogs nothing. Fresh, unparseable and non-`v-` accounts are untouched.
- [x] The reconciler completes revocations queued during an outage before OpenBao's own retry, on both engines.
- [x] An irrevocable lease is detected, alerted and revoked.
- [x] The reconciler token is refused everything else (5.5).
- [x] PostgreSQL: revoke while the primary is down. The revoked role is refused on the replica within one reconciler interval plus 2 s (measured 3.8 to 12.7 s) and its open session is terminated; a replica restart during the outage gives no login window; still-valid roles keep working, except those issued in the same seconds (documented over-deny).
- [x] Malicious deny descriptors (quotes, newlines, `all`, `+group`, `@file`, `replicator`, `bao_admin`, `postgres`, path traversal, symlink, oversized, FIFO and others) are rejected and alerted, and `pg_hba` is unchanged.
- [x] MariaDB `SELECT ... INTO OUTFILE` and `LOAD_FILE` are denied.
- [x] Audit entries in the database logs show the temp username. The log store joins person, lease id, username and the query on the replica, with client host.
- [x] The OpenBao audit log maps the temp username to the person.
- [x] No cleartext temp password appears in database logs. Met on both engines. PostgreSQL: pgAudit redaction, SCRAM, `log_statement = none`. MariaDB: replica-only temp users, also proven by a pattern scan of every decoded binary and relay log (see 4.E).
- [x] The apps still pass smoke tests after every phase (phases 0 to 4).
- [x] The `docker exec` bypass is documented and its alert fires (as `superuser_login`). No notification channel yet.
- [x] Phase 5: one request gives one trace across browser, API and SQL, and the request's log lines carry the same `trace_id` (both APIs; browser path checked by hand).
- [x] Phase 5: customer data sent through both APIs appears in no trace and no log line; SQL is recorded with placeholders only; e-mail addresses in browser logs are masked.
- [x] Phase 5: no telemetry container mounts an audit volume or the store; the apps reach Alloy but not Loki, Tempo or Grafana; only Grafana is published, on loopback; Loki holds no audit records.
- [x] Phase 5: Grafana admits only Keycloak users in `app1-devs` (Viewer with Explore, no write permissions); others, anonymous access and the local admin over HTTP are refused.

### 7.5 Known weaknesses found in the prototype

- **Phase 5, host-to-container requests (open).** On the phase 5 stack, `phase4-checks.ps1` fails 2 of 96 checks in two runs: some of its Windows PowerShell requests to `http://localhost:8080` (4 Laravel POSTs during the churn, and a few of 20 GETs) time out. nginx logged every request it received as 200 or 201 and logged no 499 or 504, so the lost requests never reached the container: they were dropped in Docker Desktop's port forwarding. In a separate probe, `Invoke-WebRequest` lost 3 of 40 requests to `127.0.0.1:8080` and none of 40 to `localhost`; curl lost none of 120. Not yet determined: whether the phase 4 stack shows the same on this host now, and whether the extra load of phase 5 contributes. The two checks' database and replication assertions pass.
- **Phase 5 memory.** Grafana 13 needs about 430 MiB right after start; with a 192 MiB limit its first start stalled at full CPU, so the limit is 512 MiB with `GOMEMLIMIT=350MiB`. The telemetry services together use about 810 MiB; the whole phase 5 stack about 1.9 GiB.
- **Phase 5 lab shortcuts.** OTLP and the store APIs have no TLS and no authentication (isolation by internal networks only); every trace is sampled; Grafana's `viewers_can_edit` is deprecated in Grafana 13 (it still gives Viewers Explore; a custom role will be needed when it is removed).

- **MariaDB revocation no longer depends on the replica being reachable for logins** (three backstops, 5.4). Residual: every replica restart also drops the users of valid leases; a failed `bao lease revoke -sync` is still not retried (its user goes at the next replica start or at lease expiry).
- **PostgreSQL primary outage (closed by the replica deny list, 5.4).** Residual risks:
  - Detection depends on OpenBao and the reconciler. A revoked role can log in for up to one reconciler interval plus 2 s (about 62 s with the proposed 60 s interval).
  - Roles of the same OpenBao role issued within the 4-second window are over-denied, until 60 s after the lease is gone.
  - A role whose name was generated more than 3 s before its lease was issued would not be matched, and the scheme depends on the username template (setup refuses a different one).
  - The descriptor volume is single-host.
  - The watcher acts as local superuser.
  - SIGKILL of its supervisor restarts every replica session.
  - A compromised reconciler can deny or un-deny temp roles (no more than revoking them) but cannot inject `pg_hba` tokens (tested).
  - The deny-applied alert waits until SQL works.
  - The healthcheck now includes the watcher heartbeat.
  - The image now includes tini.
- The lease reconciler is a new credential (role ID and secret ID files; the secret ID never expires in the lab). Its token can list every database lease ID and revoke any database lease (a denial-of-access risk), and holds `sudo` on `sys/leases/lookup/database/creds/*` and `sys/leases`. Mitigated by the /32 binding. Production: a response-wrapped secret ID with TTL and use limit rotated by the orchestrator, or platform identity (Kubernetes or cert auth).
- The reconciler cannot see a failed `-sync` revoke, because that lease is still valid.
- Alert noise during an outage: `revocation_retried_by_reconciler` fires about every 30 s per pending lease.
- Availability: every replica restart drops the users of valid leases; a crash loop keeps ending developer sessions.
- The event definer's privileges are dangerous if someone can change the event. `ALTER EVENT` without `DEFINER` silently runs it as the altering user.
- `--secure-file-priv` now limits root's `LOAD_FILE` and `INTO OUTFILE` on the replica (behaviour change).
- Backstop files are 0644 (MariaDB forces it), protected only by the 2750 directories. There is no rotation or retention of them.
- There is no `server_audit` record of the event's drops. If the definer loses `FILE`, the drop leaves no record and raises no alert.
- The purge and the backstop assume that no `v-` account ever replicates from the primary.
- A network partition (replica running but unreachable by OpenBao) gets no purge. The reconciler covers it once the path is back (untested).
- An OpenBao restart makes the reconciler log `action=error` until OpenBao is unsealed, then `action=recovered`.
- `bao_replica_admin` holds global `CREATE USER` and `READ ONLY ADMIN` on the replica. A compromised OpenBao can alter, lock or drop any replica account (sweeper, healthcheck, `root@localhost`).
- Its `BINLOG ADMIN` also allows `PURGE BINARY LOGS` on the replica. Its `CONNECTION ADMIN` allows killing any session there.
- The replica has a second administrative network path (`bao-replica`).
- The replica's own binary log makes an accidental local write without `sql_log_bin = 0` fatal to replication under `gtid_strict_mode`. The guard prevents it for OpenBao's statements only.
- The replicated `bao_admin` account still exists on the replica, without a network path to it.
- The seed runs with auditing off for its duration (the OFF and ON statements stay in the log).
- Laravel secrets are exported into the PHP-FPM process environment.
- File-backed Compose secrets are world-readable inside containers on Docker Desktop.
- MariaDB accounts use `mysql_native_password`.
- The lab keeps the OpenBao unseal key and root token in files and never revokes the root token.
- Keycloak runs in dev mode over HTTP.
- The log store is out of reach of the containers but not of anyone with Docker or host access, and it has no retention or rotation. Production needs an off-host, append-only store.
- Source logs are writable by each database or OpenBao process. A superuser able to write files could truncate them in the roughly one-second window before shipping.
- Superusers can turn auditing off (PostgreSQL `SET pgaudit.log`, MariaDB `SET GLOBAL server_audit_logging`). Only the superuser-login alert covers this.
- pgAudit's redaction drops `VALID UNTIL` and `CONNECTION LIMIT` from the record. The OpenBao audit log holds the lease TTL instead.
- The lab's tests deliberately leave the PostgreSQL case-B reproduction in the primary log and the store: one revoked temp password and one SCRAM verifier (the "leak reproduced" checks).
- Stale users are detected (report-only, on the PostgreSQL primary and the MariaDB replica). Cleanup: MariaDB automatic (event); PostgreSQL report-only.
- .NET rejection of a bad server certificate was not tested.
- The MariaDB replicator password is stored in clear text in `master.info` on the replica.
- The prototype's replicator has broad dump privileges (see seeding in 5.1).
- Orphaned MariaDB sessions (account dropped without a kill) keep reading until the sweeper runs.
- A compromised sweeper could kill any non-superuser session on its replica (`pg_signal_backend`). On MariaDB it could probably kill replication threads too (`CONNECTION ADMIN`). Not tested.
- `hot_standby_feedback = off` means long developer queries on the PostgreSQL replica can be cancelled after 30 s of conflict.
- Not exercised by tests (read only): re-clone after an interrupted `pg_basebackup`, re-seed after a half-finished MariaDB seed, the effect of `max_slot_wal_keep_size`, standby query cancellation.
- Not tested by running (phase 4): log rotation while tailing, changing `server_audit` filters at runtime, reading the binlog over the replication protocol.

---

## 8. Open questions

- The assumptions in section 1: read replicas, Keycloak, VPN, ticket system, GDPR, organization size.
- Real PostgreSQL and MariaDB versions in production (PostgreSQL 16+ is required for the `CREATEROLE` model).
- How many apps and databases need roles, and how to template their creation.
- Existing log infrastructure, and whether it can receive the audit logs.
- Who holds the OpenBao unseal keys.

---

## 9. Sources

- Teleport Community Edition license change (v16): https://goteleport.com/blog/teleport-community-license
- Teleport license text: https://scancode-licensedb.aboutcode.org/teleport-ce-2024.LICENSE
- Teleport feature matrix: https://goteleport.com/docs/feature-matrix/
- OpenBao database secrets engine: https://openbao.org/docs/secrets/databases/
- OpenBao PostgreSQL database plugin API: https://openbao.org/docs/api/secret/databases/postgresql/
- OpenBao MySQL/MariaDB database plugin API: https://openbao.org/docs/api/secret/databases/mysql-maria/
- OpenBao username templating: https://openbao.org/docs/concepts/username-templating/
- OpenBao audit configuration: https://openbao.org/docs/configuration/audit/
- OpenBao with Keycloak OIDC: https://openbao.org/docs/auth/jwt/oidc-providers/keycloak/
- OpenBao leases: https://openbao.org/docs/concepts/lease/
- PostgreSQL hot standby: https://www.postgresql.org/docs/17/hot-standby.html
- PostgreSQL role attributes: https://www.postgresql.org/docs/17/role-attributes.html
- PostgreSQL ALTER DEFAULT PRIVILEGES: https://www.postgresql.org/docs/17/sql-alterdefaultprivileges.html
- PostgreSQL pg_hba.conf: https://www.postgresql.org/docs/17/auth-pg-hba-conf.html
- pgAudit: https://github.com/pgaudit/pgaudit
- MariaDB SET DEFAULT ROLE: https://mariadb.com/kb/en/set-default-role/
- MariaDB DROP USER: https://mariadb.com/kb/en/drop-user/
- MariaDB user password expiry: https://mariadb.com/kb/en/user-password-expiry/
- MariaDB KILL: https://mariadb.com/kb/en/kill/
- Docker Desktop licence terms: https://docs.docker.com/subscription/desktop-license/
- Sentry self-hosted licence (FSL): https://github.com/getsentry/self-hosted/blob/master/LICENSE.md
- HashiCorp Vault licence (BUSL): https://github.com/hashicorp/vault/blob/main/LICENSE
- JumpServer: https://github.com/jumpserver/jumpserver
- Bytebase pricing: https://www.bytebase.com/pricing/
- hoop.dev pricing: https://hoop.dev/pricing
- Warpgate: https://github.com/warp-tech/warpgate
