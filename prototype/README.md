# Security prototype

Phase 0 (`compose.phase0.yaml`) is the insecure baseline. Phase 1 (`compose.phase1.yaml`) is the hardened version of the same stack; see "Phase 1: hardened stack" below. Phase 2 (`compose.phase2.yaml`) adds just-in-time developer access through OpenBao and Keycloak; see "Phase 2" below. Phase 3 (`compose.phase3.yaml`) moves developer access to read replicas and adds session sweepers; see "Phase 3" below. Phase 4 (`compose.phase4.yaml`) adds database audit logging, log shipping to a separate store and lab alert rules; see "Phase 4" below.

## Phase 0

Phase 0 is the deliberately insecure "before" baseline of the stack. It works end to end, but it has none of the hardening that later phases add. Do not run it on an exposed machine.

Stack: Angular app behind nginx (`web`), a .NET API (`dotnet-api`) on PostgreSQL 17 (`pg-primary`), and a Laravel API (`laravel-api`) on MariaDB 11.8 (`maria-primary`).

## Deliberate weaknesses

Each one is marked `# PHASE0-INSECURE:` in `compose.phase0.yaml`. Search for that string.

- Weak passwords in plain text in the compose file (no secrets, no `.env`).
- Both database ports are published to the host (5432 and 3306).
- MariaDB root can log in from any host.
- Both APIs connect as a superuser (`postgres`, `root`) instead of a least-privilege account.
- Both APIs run migrations at startup, so they hold schema-changing rights.
- Laravel runs with `APP_DEBUG=true` and a throwaway `APP_KEY` stored in the file.
- One flat network: every container can reach every other container, including the databases.
- Plain HTTP only, no TLS.

## Start

```powershell
docker compose -f compose.phase0.yaml up -d --build
```

The first start runs migrations, so give it a minute or two. The app is at http://localhost:8080.

## Smoke test

Windows PowerShell 5.1 or later:

```powershell
powershell -ExecutionPolicy Bypass -File .\tests\smoke.ps1
```

Parameters: `-BaseUrl` (default `http://localhost:8080`), `-Phase` (default `0`), `-TimeoutSeconds` (default `180`). In phase 0 the open database ports are reported as the expected insecure baseline. With `-Phase 1` or higher an open database port fails the test.

## Stop and wipe

```powershell
docker compose -f compose.phase0.yaml down -v
```

`-v` also deletes the database volumes, so the next start is a clean first run.

## Phase 1: hardened stack

`compose.phase1.yaml` runs the same apps with the hardening from sections 4.A and 4.B of `prod-db-access-hardening.md`. Phase 0 and phase 1 both use host port 8080 and do not fit in memory together, so stop one before starting the other.

What changes:

- Each app has two database accounts. `app1_migrator` owns the schema and runs DDL. `app1_runtime` has only SELECT, INSERT, UPDATE and DELETE. Accounts are created at first database start by `config/postgres/10-app1-roles.sh` and `config/mariadb/10-app1-users.sh`.
- Migrations run in one-off services (`dotnet-migrate`, `laravel-migrate`) with the migrator credential. The APIs start only after their migrate service exits with code 0, and never receive the migrator credential.
- All passwords, connection strings and the Laravel APP_KEY are Docker secrets read from `secrets\` and mounted under `/run/secrets`. Nothing secret is in the compose file, the images or container environment variables.
- No database port is published. Only `web` publishes 8080. Four networks with fixed subnets: `edge` (web), `web` (internal: web and both APIs), `app1-pg` (internal: .NET side and PostgreSQL), `app1-maria` (internal: Laravel side and MariaDB).
- TLS on both databases with a lab CA. The one-shot `pki-init` service writes the CA and server certificates into named volumes. App containers mount only `ca.crt` and verify the server certificate.
- PostgreSQL uses its own `pg_hba.conf`: `postgres` only over the local socket (peer), the two app roles only with `hostssl` from the `app1-pg` subnet, everything else rejected. MariaDB has `require_secure_transport=ON`, root only as `root@localhost`, and app accounts limited to the `app1-maria` subnet with `REQUIRE SSL`.
- Laravel runs with `APP_ENV=production` and `APP_DEBUG=false`.

### Generate secrets

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\gen-secrets.ps1
```

This writes random values into `secrets\` (git-ignored). It keeps files that already exist. `-Force` overwrites them, but the databases keep the passwords they were created with, so after `-Force` wipe the volumes (see below).

### Start

```powershell
docker compose -f compose.phase0.yaml down
docker compose -f compose.phase1.yaml up -d --build
```

`pki-init`, `dotnet-migrate` and `laravel-migrate` run once and exit with code 0. That is expected.

### Test

```powershell
powershell -ExecutionPolicy Bypass -File .\tests\smoke.ps1 -Phase 1
powershell -ExecutionPolicy Bypass -File .\tests\phase1-checks.ps1
```

`phase1-checks.ps1` checks network isolation, database privileges, TLS, superuser lockdown, secrets and migration exit codes against the running stack. Each negative check prints the actual error text and passes only if that text matches the control under test.

### Stop and wipe

```powershell
docker compose -f compose.phase1.yaml down -v
```

`-v` deletes the database and certificate volumes. The next start creates new databases, accounts and certificates from the files in `secrets\`. To also rotate every secret, delete `secrets\` (or use `-Force`) and run `gen-secrets.ps1` again before the next start.

## Phase 2: just-in-time developer access

`compose.phase2.yaml` is phase 1 plus OpenBao and Keycloak (sections 4.C, 4.E and 5 of `prod-db-access-hardening.md`). A developer in the Keycloak group `app1-devs` logs in to OpenBao and gets a temporary, read-only database user that sees only masked views. Only one stack fits at a time, so stop phase 1 first.

What it adds:

- OpenBao 2.7.2 (MPL-2.0) from `config/openbao/bao.hcl`, not dev mode: Raft storage on the `bao-data` volume, TLS listener with a lab CA certificate (`pki-init` now also issues one for `openbao`), and a file audit device declared in the config (`bao-audit` volume). OpenBao starts sealed after every restart.
- Keycloak 26.8.2 (Apache-2.0) in dev mode with the realm `lab` imported from `config/keycloak/lab-realm.json`: group `app1-devs`, user `alice` (in it), user `bob` (not in it), a group mapper that emits `groups` without the path, username editing disabled.
- Database side, set up by `scripts/phase2-setup.ps1` after the migrations: PostgreSQL schema `debug` and MariaDB database `app1_masked` with masked views (`email`, `full_name`), role `debug_ro`, admin account `bao_admin`.
- Networks: `bao-admin` (internal: OpenBao at 10.81.4.10 and both primaries), `access` (internal: where developers connect; the primaries are on it as the no-replica fallback, marked `PHASE2-FALLBACK`), `lab` (OpenBao and Keycloak, published on 127.0.0.1 only). No database port is published.
- OpenBao: database secrets engine with roles `app1-pg-ro` and `app1-maria-ro` (1 h, max 4 h), policy `app1-debug`, auth methods `oidc` (interactive) and `jwt` (automated tests), identity group `app1-devs`.

LAB-ONLY shortcuts, do not copy to production:

- OpenBao is initialized with one key share. `phase2-setup.ps1` writes the unseal key and the root token to `secrets\openbao_unseal_key` and `secrets\openbao_root_token` in plain text, and the root token is not revoked.
- Keycloak runs in dev mode over plain HTTP with an in-container database. The test passwords of `alice` and `bob` are in `config/keycloak/lab-realm.json`.
- The Keycloak client `bao-jwt-test` allows the password grant so the tests can get tokens without a browser.

### Start and set up

```powershell
docker compose -f compose.phase1.yaml down
powershell -ExecutionPolicy Bypass -File .\scripts\gen-secrets.ps1
docker compose -f compose.phase2.yaml up -d --build
powershell -ExecutionPolicy Bypass -File .\scripts\phase2-setup.ps1
```

`gen-secrets.ps1` now also writes the initial `bao_admin` passwords, the Keycloak admin password and the `openbao` client secret. `phase2-setup.ps1` waits for the migrations and Keycloak, runs the database setup, initializes and unseals OpenBao and writes its whole configuration. It is idempotent: run it again at any time. Right after OpenBao connects to each database it rotates the `bao_admin` password (`rotate-root`), so the initial passwords in `secrets\` stop working and only OpenBao knows the current ones.

### Test

```powershell
powershell -ExecutionPolicy Bypass -File .\tests\smoke.ps1 -Phase 1
powershell -ExecutionPolicy Bypass -File .\tests\phase1-checks.ps1 -ComposeFile .\compose.phase2.yaml -Project security-prototype-phase2
powershell -ExecutionPolicy Bypass -File .\tests\phase2-checks.ps1
```

`phase2-checks.ps1` takes about three minutes. It logs in as `alice` and `bob` through Keycloak and OpenBao, uses the temporary credentials from throwaway database clients on the `access` network, revokes them while a session is open, lets a shortened lease expire, and restarts and unseals OpenBao once.

### Try the interactive login in a browser

1. Open https://localhost:8200/ui/ . The browser warns about the certificate because the lab CA is not trusted on the host. Accept the warning for this site.
2. Method: OIDC. Role: leave empty (default `dev`). Click "Sign in with OIDC Provider".
3. A Keycloak window opens on http://keycloak.localhost:8180 . Sign in as `alice` with the password from `config/keycloak/lab-realm.json`. Allow pop-ups for localhost if the window does not open.
4. Back in OpenBao, open the browser console of the UI (the ">_" button at the top) and run `read database/creds/app1-pg-ro`. Repeat the login as `bob` to see the permission error.

Alternative without the certificate warning: the `bao` CLI in a throwaway container, with its OIDC callback port published on 127.0.0.1:8250 (nothing is installed on the host):

```powershell
docker run --rm -it --network security-prototype-phase2_lab -p 127.0.0.1:8250:8250 -v security-prototype-phase2_pki-ca:/pki-ca:ro -e BAO_ADDR=https://openbao:8200 -e BAO_CACERT=/pki-ca/ca.crt --entrypoint sh openbao/openbao:2.7.2
bao login -method=oidc role=dev listenaddress=0.0.0.0 port=8250 skip_browser=true
```

Open the printed `http://keycloak.localhost:8180/...` link in the browser and sign in. The browser then shows "OpenBao Authentication Succeeded" and the CLI is logged in. Then run `bao read database/creds/app1-pg-ro` and, when finished, `bao token revoke -self`.

`*.localhost` names resolve to 127.0.0.1 in current browsers without a hosts-file entry. Inside Docker the same name is a network alias of the Keycloak container, and Keycloak listens on 8180 inside and outside, so the issuer URL is the same for the browser and for OpenBao.

To connect with the credentials, run a client on the `access` network, for example:

```powershell
docker run --rm -it --network security-prototype-phase2_access -v security-prototype-phase2_pki-ca:/ca:ro postgres:17 psql "host=pg-primary dbname=app1 user=<username> sslmode=verify-full sslrootcert=/ca/ca.crt"
```

### Unseal after a restart

OpenBao is sealed after `docker compose restart openbao`, a Docker Desktop restart or a reboot. Data, leases and rotated passwords are kept.

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\phase2-unseal.ps1
```

If Keycloak is recreated it imports the realm again from the seed file. If you edit `config/openbao/bao.hcl` or another mounted config file while the stack runs, recreate that container (`docker compose -f compose.phase2.yaml up -d --force-recreate openbao`) and unseal again.

### Stop and wipe

```powershell
docker compose -f compose.phase2.yaml down -v
Remove-Item .\secrets\openbao_unseal_key, .\secrets\openbao_root_token
```

`-v` deletes the database, certificate and OpenBao volumes. OpenBao and the databases must always be wiped together: after a wipe of only OpenBao, nobody knows the rotated `bao_admin` passwords (reset them through the local superuser). Remove the two OpenBao files as well, because they belong to the deleted OpenBao instance. To rotate everything, delete `secrets\` and run `gen-secrets.ps1` again.

## Phase 3: read replicas and session sweepers

`compose.phase3.yaml` (project `security-prototype-phase3`) is phase 2 plus a read replica per database and a session sweeper per replica (sections 4.B, 4.C, 5.1 and 5.4 of `prod-db-access-hardening.md`). OpenBao still creates the temporary users on the primaries; they replicate, and developers can use them only on the replicas. Phase 2 and phase 3 use the same subnets and host ports, so only one of them can run at a time.

What changes compared with phase 2:

- `pg-replica`: PostgreSQL hot standby, physical streaming replication from `pg-primary` as role `replicator` over TLS (`sslmode=verify-full`, own certificate from the lab CA), through the physical slot `pg_replica`. On first start `config/postgres/replica-entrypoint.sh` clones the primary with `pg_basebackup`; later starts skip that (marker file `replica-bootstrap.done`). `max_standby_streaming_delay=30s` and `hot_standby_feedback=off` are set explicitly (reasons in the compose file).
- `maria-replica`: MariaDB GTID replica, `read_only=ON`. On first start `config/mariadb/20-replica-seed.sh` takes a consistent dump of the primary including the `mysql` database (`--single-transaction --gtid --master-data=2`), loads it and starts replication at the dump's GTID with `MASTER_SSL=1` and `MASTER_SSL_VERIFY_SERVER_CERT=1`. The account `replicator` exists only for the replica's address, with `REQUIRE SSL`.
- Networks: `pg-repl` and `maria-repl` (internal) carry replication. The primaries are no longer on `access`; of the databases only the replicas are. OpenBao still reaches the primaries through `bao-admin`. No database port is published.
- `pg_hba.conf`: on the primary the `PHASE2-FALLBACK` line is gone, every `+debug_ro` login is rejected and `replicator` is allowed only from the replica's address. On the replica `bao_admin` is rejected first (it is a member of `debug_ro`), then `+debug_ro` from the access subnet and `session_sweeper` from the sweeper's address.
- MariaDB temp users keep the host mask `10.81.5.0/255.255.255.0` (the access subnet). The primary is not on that network, so the account can never match a connection to the primary.
- `pg-sweeper` and `maria-sweeper` (`config/sweeper/`): small loops on the access network with fixed addresses, using the `postgres:17` and `mariadb:11.8` images for their clients. Every `SWEEP_INTERVAL_SECONDS` (10 in the lab; the proposal says 60 for production) they end replica sessions whose user was dropped (and, in PostgreSQL, `v-` roles whose `VALID UNTIL` has passed), and log one line per session. Their accounts are created on the primaries by `scripts/phase3-setup.ps1` and replicate: PostgreSQL `session_sweeper` has only `pg_signal_backend` and `CONNECT` on `app1`; MariaDB `session_sweeper` has `PROCESS`, `CONNECTION ADMIN` and `SELECT (User) ON mysql.user`.

LAB-ONLY, in addition to the phase 2 list: the phase 3 OpenBao instance keeps its unseal key and root token in `secrets\openbao_phase3_unseal_key` and `secrets\openbao_phase3_root_token`; the MariaDB `replicator` account also has the read privileges the seed dump needs.

### Start and set up

```powershell
docker compose -f compose.phase2.yaml down
powershell -ExecutionPolicy Bypass -File .\scripts\gen-secrets.ps1
docker compose -f compose.phase3.yaml up -d --build
powershell -ExecutionPolicy Bypass -File .\scripts\phase3-setup.ps1
```

`gen-secrets.ps1` now also writes `pg_replicator_password`, `maria_replicator_password`, `pg_session_sweeper_password` and `maria_session_sweeper_password`. `phase3-setup.ps1` runs `phase2-setup.ps1` against the phase 3 stack, creates the sweeper accounts on the primaries and waits until both replicas are healthy and caught up. It is idempotent. The sweepers log connection errors until the setup has created their accounts; that is expected.

### Test

```powershell
powershell -ExecutionPolicy Bypass -File .\tests\smoke.ps1 -Phase 1
powershell -ExecutionPolicy Bypass -File .\tests\phase1-checks.ps1 -ComposeFile .\compose.phase3.yaml -Project security-prototype-phase3
powershell -ExecutionPolicy Bypass -File .\tests\phase2-checks.ps1 -ComposeFile .\compose.phase3.yaml -Project security-prototype-phase3 -BaoSecretPrefix openbao_phase3 -PgDevHost pg-replica -MariaDevHost maria-replica
powershell -ExecutionPolicy Bypass -File .\tests\phase3-checks.ps1
```

`phase2-checks.ps1` with `-PgDevHost` / `-MariaDevHost` runs the developer-side checks against the replicas. On a replica a write is refused by the read-only server before the privilege check, so those checks then also accept the read-only error; `phase3-checks.ps1` checks the write privileges on the primary's catalog. `phase3-checks.ps1` takes about four minutes. It stops and starts the sweepers once (control case) and the replicas once (revoke while a replica is down), and briefly points MariaDB replication at the primary's IP address to show that the certificate name is checked. It prints the measured replication lag and the time from revoke or expiry to the end of a replica session.

Optional, report-only: `scripts\phase3-stale-users.ps1` lists `v-` users on the primaries that outlived the role's `max_ttl` (4 h) plus a margin (PostgreSQL by `VALID UNTIL` and by the creation time in the name, MariaDB by the creation time in the name and `password_last_changed`). It drops nothing; exit code 3 means it found some.

### Try a replica login by hand

Get credentials as in phase 2 (OIDC in the browser or the `bao` CLI container, now with the phase 3 project name in the network and volume names), then connect from a client on the `access` network:

```powershell
docker run --rm -it --network security-prototype-phase3_access -v security-prototype-phase3_pki-ca:/ca:ro postgres:17 psql "host=pg-replica dbname=app1 user=<username> sslmode=verify-full sslrootcert=/ca/ca.crt"
docker run --rm -it --network security-prototype-phase3_access -v security-prototype-phase3_pki-ca:/ca:ro mariadb:11.8 mariadb -h maria-replica -u <username> -p --ssl-ca=/ca/ca.crt --ssl-verify-server-cert app1_masked
```

`SELECT * FROM debug.customers` (PostgreSQL) or `SELECT * FROM customers` (MariaDB) shows the masked rows. The same credentials against `pg-primary` or `maria-primary` fail: the name does not resolve on the access network. Revoke the lease (`bao lease revoke <lease_id>`) while the session is open and watch the sweeper end it:

```powershell
docker compose -f compose.phase3.yaml logs -f pg-sweeper maria-sweeper
```

### Unseal after a restart

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\phase2-unseal.ps1 -ComposeFile .\compose.phase3.yaml -Project security-prototype-phase3 -BaoSecretPrefix openbao_phase3
```

Docker Compose does not recreate a container when only the content of a mounted config file changes. After editing a file under `config\`, run `docker compose -f compose.phase3.yaml up -d --force-recreate <service>` (and unseal again if it was `openbao`). A replica restart resumes replication; it does not clone or seed again.

### Stop and wipe

```powershell
docker compose -f compose.phase3.yaml down -v
Remove-Item .\secrets\openbao_phase3_unseal_key, .\secrets\openbao_phase3_root_token
```

## Phase 4: database audit logging and log shipping

`compose.phase4.yaml` (project `security-prototype-phase4`) is phase 3 plus database audit logging on all four database servers, shipping of every audit log to a store that only the shipper mounts, and lab alert rules (section 4.E of `prod-db-access-hardening.md`, workstream E). Phase 3 and phase 4 use the same subnets and host ports, so only one of them can run at a time.

What it adds:

- `pg-primary` and `pg-replica` run `security-prototype-phase4-postgres-pgaudit`, built from `images/postgres-pgaudit/Dockerfile`: `postgres:17` plus `postgresql-17-pgaudit` 17.1 (PostgreSQL License) from the PGDG apt repository the image already has, and Debian's `tini` 0.19.0 (MIT; used only by `pg-replica`'s deny-list watcher, see "Revocation backstops"). Both log in PostgreSQL's own JSON format (`log_destination=jsonlog`, logging collector) to files on their own volume, with `log_connections` and `log_disconnections` on. The settings are on the server command line in the compose file, so `ALTER SYSTEM` cannot override them.
  - Primary: `pgaudit.log = 'ddl, role'`: migrations and everything `bao_admin` does per lease (`CREATE ROLE`, `GRANT`, `ALTER ROLE ... SET`, `DROP ROLE`). The application's reads and writes are not audited (volume; developers cannot reach the primary).
  - Replica: `pgaudit.log = 'read, write, ddl, role, misc_set'` with `log_catalog = on`: every statement of a temp user, including catalog queries. Writes, DDL and role statements are refused by the standby; the refusal is logged as an `ERROR` with the statement.
  - Role settings (`config/postgres/phase4-audit-roles.sh`, run at first init before the other init scripts and again by the setup): `postgres` gets `read, write, ddl, role, misc_set` with `log_catalog = off` (the healthcheck and test polls), `session_sweeper` gets `log_catalog = off`. The `role` class is safe for the setup scripts' `CREATE/ALTER ROLE ... PASSWORD`, because pgAudit redacts the password (see below). Temp users and `debug_ro` have no role setting: a setting on `debug_ro` would not reach its members.
- `maria-primary` and `maria-replica` load the bundled `server_audit` plugin with `--server-audit=FORCE_PLUS_PERMANENT` (the server does not start without it, `UNINSTALL PLUGIN` fails) and write `/var/log/mariadb-audit/server_audit.log` on their own volume. Both log `CONNECT,QUERY`. `server_audit_incl_users` has no wildcard for `v-*`, so the noisy known accounts are excluded instead: `healthcheck,app1_runtime` on the primary, `healthcheck,session_sweeper` on the replica. `CONNECT` events are written for excluded users too. The general log and the slow log are explicitly off.
- OpenBao uses `config/openbao/bao.phase4.hcl`: the same file audit device with mode `0640` instead of `0600`, on the `bao-audit` volume (owner openbao, group 4000).
- The sweepers' stdout is also appended to a file on their own volume (`tee`); `docker logs` is unchanged.
- `fluent-bit` (Fluent Bit 5.1.5, Apache-2.0, `config/fluent-bit/`): reads the PostgreSQL JSON logs, the `server_audit` files, the OpenBao audit file and the sweeper files from volumes mounted READ-ONLY, normalizes every record (`audit.lua`) and writes one JSON object per line to the `log-store` volume: `audit.jsonl` (everything) and `alerts.jsonl` (a copy of each record that matched an alert rule). It has no network (`network_mode: none`), runs as uid 4001 with group 4000, has a read-only root file system and no capabilities, and never sees the Docker socket. `log-store` is mounted by no other long-running container.
- `log-init` (one-shot, no network) sets ownership: each source log directory belongs to its writer (postgres/mysql 999, openbao 100) with group 4000 and mode 2750 (setgid); the store belongs to uid 4001.
- MariaDB root rotation: `app1-maria` (bao_admin on the primary) uses `root_rotation_statements = SET PASSWORD = PASSWORD('{{password}}')` from its first rotate-root (`phase4-setup.ps1` passes it to `phase2-setup.ps1`). The phase 2/3 form (`ALTER USER ... IDENTIFIED BY '{{password}}'`) is written to the MariaDB binary log in clear text; `SET PASSWORD` for the current user is binlogged as a hash.
- **MariaDB temp users on the replica only** (fix for the binary-log password leak, design 4.E):
  - OpenBao creates and drops the MariaDB temp users on `maria-replica`, never on the primary. Connection `app1-maria-replica`: account `bao_replica_admin`, URL `{{username}}:{{password}}@tcp(maria-replica-admin:3306)/?sql_log_bin=0`, TLS name `maria-replica`. The role `app1-maria-ro` points at it; `app1-maria` (bao_admin on the primary) keeps only the LAB-ONLY probe roles.
  - `?sql_log_bin=0`: the Go MySQL driver sends `SET sql_log_bin=0` on every new connection, so nothing OpenBao does on the replica is binlogged. It cannot go into the statements: OpenBao runs every statement list in a transaction, and MariaDB refuses `SET SESSION sql_log_bin` (and `SET STATEMENT sql_log_bin=0 FOR ...`) there (Error 1694, measured). Each statement list starts with a guard, `SET @sql_log_bin_must_be_0 = (SELECT 1 UNION ALL SELECT 1 FROM DUAL WHERE @@session.sql_log_bin <> 0)`, which fails with Error 1242 if the parameter is missing. Without both, a local `CREATE USER` got a GTID `0-2-n` in the replica's binlog and the next primary write stopped replication (gtid_strict_mode, measured).
  - `bao_replica_admin` exists only on the replica (created by `config/mariadb/phase4/replica-bao-account.sh` with `sql_log_bin = 0`, so it is in no binlog and not on the primary), host `10.81.9.10`, `REQUIRE SSL`. Privileges, each measured by removing it (`tests\phase4-checks.ps1`): `CREATE USER` (create/drop), `READ ONLY ADMIN` (the replica is `read_only`; also needed for its own `SET PASSWORD`), `BINLOG ADMIN` (to set `sql_log_bin`; `SUPER` is not enough in 11.8), `CONNECTION ADMIN` (`KILL USER`; without it `KILL USER` silently kills nothing), `SELECT ON app1_masked.* WITH GRANT OPTION`. Its first password is generated by `phase4-setup.ps1` in memory, set with `SET PASSWORD FOR` (masked by server_audit, not binlogged), handed to OpenBao on stdin and rotated at once. If the replica is re-seeded the account is lost; the next `phase4-setup.ps1` run notices (OpenBao cannot connect) and creates it again.
  - Network `bao-replica` (10.81.9.0/24): only `openbao` (.10) and `maria-replica` (.12, alias `maria-replica-admin` on this network only). Not `bao-admin`: measured, with the replica on `bao-admin` the name `maria-primary` resolved to the primary's bao-admin address, the replication IO thread connected from the wrong address and the primary refused it (replication stopped); it would also give the developer-facing replica a route to both primaries' admin ports and let OpenBao log in to the replica as the replicated `bao_admin@10.81.4.10`. Not `access`: that is the developers' network.
  - The replica keeps its own binary log (`--log-bin`, `--log-slave-updates`, ROW) like a failover candidate; it contains only replicated events (GTIDs `0-1-n`), never OpenBao's local statements.
  - Revocation is local now: `KILL USER` in the revocation statement ends open replica sessions at once, with or without the sweeper. The sweeper stays as a second line (sessions whose account vanishes without a kill, for example after a re-seed). `DROP USER IF EXISTS`: revoking a user that a re-seed already removed succeeds.
  - Revoke while the replica is down: OpenBao cannot reach it. An asynchronous revoke (the default of `bao lease revoke`, also used for token revocation and TTL expiry) is queued and retried with growing, jittered delays (OpenBao logs each `next_attempt`; measured for example 4 s, 26 s, 22 s, 43 s, 3m12 s for one lease and 4 s, 29 s, 35 s, 1m41 s for another); after the sixth failure (about 10 to 11 minutes) the lease becomes irrevocable. `bao lease revoke -sync` fails and is not retried. Before the revocation backstops (next item) the user then existed on the restarted replica until OpenBao's next retry and **could log in** (measured 31 to 57 s), indefinitely after an outage of more than about 11 minutes. The backstops close that window; see "Revocation backstops".
- **Revocation backstops** (design 5.4, "Revocation depends on the replica being reachable"). Three independent layers, `tests\revocation-checks.ps1`:
  1. **Startup purge** (MariaDB). `maria-replica` runs an `init_file` at every start (`config/mariadb/phase4/replica-init.sql.tmpl`, rendered by `config/mariadb/phase4/replica-entrypoint.sh` to `/etc/mysql/replica-init/init.sql`, `--init-file`). It drops every local `v-` account with `sql_log_bin = 0` before the server answers any network connection. Every MariaDB temp user lives only on the replica and is temporary, so this is safe: a developer whose lease is still valid requests new credentials (their user is purged too), and OpenBao's later revocation still succeeds (`DROP USER IF EXISTS`). Measured on 11.8: `init_file` accepts compound statements (`BEGIN NOT ATOMIC ... FOR ... DO EXECUTE IMMEDIATE ... END FOR; END`, with `DELIMITER` or on one line), `read_only` does not block it, `SET SESSION sql_log_bin = 0` works there (without it the purge got a local GTID `0-2-n`). The listening socket exists before the `init_file` runs, so connection attempts made meanwhile wait in the kernel's listen backlog and are answered only after it (measured: no attempt answered before the purge's completion time; the first session of any account ran about 0.07 s after it). Each start writes one line, also with `dropped=0`, to `/var/log/mariadb-audit/backstop/startup-purge-<µs>.log` with `SELECT ... INTO OUTFILE`; `--secure-file-priv` limits FILE to that directory (before, it was unrestricted). Fluent Bit ships it; a non-zero count raises `replica_startup_purge`.
  2. **Expiry backstop** (MariaDB). The `init_file` also (re)creates, at every start, the local event `replica_local.revocation_backstop` (`--event-scheduler=ON`) and its definer `revocation_backstop@localhost` (locked, no password, local, `sql_log_bin = 0`). Every `BACKSTOP_INTERVAL_SECONDS` (lab 15, production proposal 300) it locks, `KILL USER`s and drops `v-` users whose creation time (the 10-digit timestamp before the random suffix, regular expression anchored at the end of the name) is older than `BACKSTOP_MAX_TTL_SECONDS` (14400, must equal the role's `max_ttl`; the test compares them) plus `BACKSTOP_MARGIN_SECONDS` (lab 300, production proposal 900), with `sql_log_bin = 0`, and logs `expiry-drop-<µs>.log`, which raises `replica_expiry_backstop` (OpenBao failed to revoke). Names without that pattern are left alone (the next startup purge drops them). The definer's privileges, each measured by removing it: `CREATE USER`, `READ ONLY ADMIN`, `BINLOG ADMIN`, `CONNECTION ADMIN` (without it `KILL USER` silently kills nothing), `FILE` (without it the drop happens but the log line, and so the alert, is lost), `SELECT (User, Host) ON mysql.global_priv`, `EVENT ON replica_local.*`. Events that arrive from the primary are created `SLAVESIDE_DISABLED` and do not run on the replica (tested). `server_audit` does not record the statements an event runs (measured); the shipped backstop line is the record. **Caution:** an `ALTER EVENT` without a `DEFINER` clause makes the altering user (root) the definer (measured); always write `ALTER DEFINER = 'revocation_backstop'@'localhost' EVENT ...`, or restart the replica (the `init_file` re-creates the event and the definer's privileges). `phase4-setup.ps1` refuses another definer.
  3. **Lease reconciler** (both engines). `lease-reconciler` (`config/reconciler/lease-reconciler.sh`, image `openbao/openbao:2.7.2` for its `bao` CLI, non-root, read-only root file system, no capabilities) runs on the internal network `bao-reconciler` (10.81.10.0/24: OpenBao .10, reconciler .20) and nothing else; it reaches no database. Every `RECONCILE_INTERVAL_SECONDS` (lab 15, production proposal 60) it lists irrevocable leases (`GET sys/leases?type=irrevocable`), logs each one under `database/creds/` once (`action=irrevocable-found`, alert `irrevocable_lease_found`) and revokes it with `sync=true`; and it lists the leases under `database/creds/` (`LIST sys/leases/lookup/database/creds/<role>/`), looks each one up (`PUT sys/leases/lookup`), and revokes with `sync=true` (`PUT sys/leases/revoke`) those with TTL 0 in two consecutive passes (`action=revoke-retried`, alert `revocation_retried_by_reconciler`, also for `outcome=failed`). Failed attempts back off per lease (1, 2, ... passes, at most `RECONCILE_MAX_BACKOFF_PASSES`, lab 2). Valid leases are never touched, so a failed `bao lease revoke -sync` is still not retried (its MariaDB user is purged at the next replica start). It authenticates with AppRole `lease-reconciler`: policy `lease-reconciler` only (`config/openbao/lease-reconciler.hcl`; each rule measured by removing it), no default policy, batch tokens of 300 s, secret ID and tokens bound to 10.81.10.20/32. Role ID and secret ID are Docker secrets from `secrets\openbao_phase4_reconciler_role_id` / `_secret_id` (written by `phase4-setup.ps1`, which issues a new secret ID and destroys the older ones at every run; `gen-secrets.ps1` writes placeholders, because Docker creates a directory in place of a secret file that is missing at `up`). They are passed to the CLI as `role_id=@file`, never on a command line or in the environment; the token lives in a shell variable and the environment of each `bao` child process. Its log (`reconciler-log` volume) is shipped.
  - Measured (lab): purge completes about 3 s after `docker compose start maria-replica`, before any connection is answered; backstop drop and session kill within one event interval; the reconciler completed revocations queued during an outage of 150 s or more within about 6 to 25 s after `maria-replica` / `pg-primary` was healthy (the test starts the databases when OpenBao's own next attempt is at least 90 s away, so the completion is the reconciler's; without that, OpenBao's jittered retry sometimes comes first). With `tests\revocation-checks.ps1 -IrrevocableTest` see the test output for the irrevocable case.
  4. **PostgreSQL replica deny list** (PostgreSQL is not covered by layers 1 and 2: the temp roles are created on `pg-primary` and replicate, and with the primary down the hot standby cannot drop a role; before this layer a revoked role kept logging in to `pg-replica` for the whole outage, 10 of 10 attempts in 150 s, bounded only by its `VALID UNTIL`). Expiry needs nothing: `VALID UNTIL` replicates and the standby enforces it. Pieces:
     - **Descriptors** (reconciler, no new OpenBao permission: `issue_time` is in the `sys/leases/lookup` response it already reads). For every lease of a role in `PG_DENY_ROLES` (`app1-pg-ro`) that has TTL <= 0 (from the first pass that sees it) or is irrevocable, it writes `/pg-deny/<role>.<lease id suffix>.deny` containing exactly `v1 <role> <issue_time as unix seconds>`, via a dot-file and `mv` (atomic), and logs `action=pg-deny-written`. It removes the file (`action=pg-deny-removed`) once OpenBao answers `invalid lease` (or the lease is valid again), never on any other error. MariaDB leases never get one. Volume `pg-deny`: owner 100:1000 mode 0755 (set by `log-init`), mounted read-write only by `lease-reconciler`, read-only by `pg-replica`, nowhere else; the two containers share no network.
     - **Watcher** (`config/postgres/pg-deny-watcher.sh`, user postgres inside `pg-replica`, no network credential). `replica-entrypoint.sh` runs it once as `apply-offline` BEFORE the server starts, then starts `tini -s -- pg-deny-watcher.sh supervise` in the background and execs the server as before (PID 1). `tini` (0.19.0, MIT, added to `images/postgres-pgaudit`) is a child subreaper: PostgreSQL 17 treats ANY unknown child of the postmaster that dies by a signal or with an exit code other than 0/1 as a crashed backend and restarts every session (measured), so nothing the watcher forks may be reparented to the postmaster. `supervise` restarts `watch` when it exits (`action=watcher-restarted`).
     - **Validation.** Only regular files (no symlink, FIFO, directory) named `^[a-z0-9][a-z0-9_-]{0,63}\.[A-Za-z0-9]{1,64}\.deny$`, read with `dd iflag=nofollow,nonblock` (at most 129 bytes, NUL bytes made visible), whose body is exactly one line `^v1 <role> [1-9][0-9]{9}$`, whose role equals the file name's and is in `PG_DENY_ALLOWED_ROLES`, and whose time is not in the future. Anything else is logged once (`action=descriptor-rejected reason=...`, file name sanitized, content never logged) and ignored. Dot files are never read. At most 100 files are examined.
     - **Enforcement.** Each valid descriptor becomes one regular expression for the temp role names its lease can have. The username template is `v-<display name, 30>-<role, 12>-<unix_time>-<random 4>` and `unix_time` is taken just before the lease is created (measured: `issue_time` minus the name's timestamp was 0 s in 29 of 30 leases and 1 s once), so the pattern is `/^v-.+-<role, first 12 chars>-(<t-3>|<t-2>|<t-1>|<t>)-[A-Za-z0-9]{4}$` (`PG_DENY_TS_WINDOW_SECONDS` 3). The patterns go to `/var/lib/postgresql/pg-deny/denied_roles` (container file system, owner postgres, 0600, directory 0700; unreachable for the reconciler), which line 2 of the replica's `pg_hba.conf` includes before every allow line: `host all @/var/lib/postgresql/pg-deny/denied_roles all reject`. Then `pg_ctl reload` (SIGHUP; works on a standby), and over the local socket (`application_name=pg-deny-watcher`, exempt from `superuser_login` like the healthcheck) `pg_terminate_backend` for every session whose `usename` matches; one `action=deny-applied` line per descriptor with the matched roles, the number of sessions ended and `over_deny=1` if more than one role matched. Every pattern starts with `^v-`, so no account other than a temp user can ever match. The watcher connects to the database only while entries exist (no idle logins).
     - **PostgreSQL 17 facts the file layout depends on** (measured in a throwaway server): regular expressions work inside an `@file`; an `@file` with no token (empty, or comments only) is a parse error, FATAL at server start and "pg_hba.conf was not reloaded" on SIGHUP, so the file always starts with the sentinel `/^$` (matches no role name); a broken file (for example an invalid regular expression) or a missing one is never loaded by a reload (the previous rules stay) and stops a server start, so the entrypoint always writes the file before the start and the watcher checks every new version with `pg_hba_file_rules` before reloading (and restores the previous one on error); the file IS re-read on every reload; `all`, `+group`, `@file`, `sameuser` and comma lists inside it are interpreted, and double quotes do not turn `/regex` into a literal there. Hence the strict validation.
     - **Release and pruning.** When the descriptor is gone (the reconciler removed it after OpenBao dropped the role on the primary), the entry stays until no role matches it any more (the `DROP ROLE` replicated), or, for a pattern that still matches a role (another lease issued in the same seconds, or a lease removed without revocation), `PG_DENY_RELEASE_GRACE_SECONDS` (60) after the removal while the standby is streaming (`action=deny-released`, then `deny-list-empty` when only the sentinel is left). Entries are kept in `/var/lib/postgresql/pg-deny/state`, so a container restart re-applies them before the server starts.
     - **Over-deny (accepted).** A still-valid role of the same OpenBao role whose name carries one of the 4 timestamps is refused too, until the grace after the revoked lease is gone (tested with two leases issued in the same second).
     - **Fail-safe.** The server always starts: the entrypoint writes the sentinel if `apply-offline` fails, and a missing descriptor directory only means no new denies (`action=error`, alert). If the watcher dies, its supervisor restarts it (alert); if the supervisor is stopped (SIGTERM), the last file stays loaded and in effect, the alert fires and the healthcheck turns unhealthy after 30 s (heartbeat file). SIGKILL of the supervisor or of `tini` makes the postmaster restart every session (alert `pg_server_process_crashed`; measured: `server process (PID n) exited with exit code 137`, all sessions terminated, read-only connections again within a second); the orphaned watcher keeps running unsupervised and the deny list stays loaded until the next container restart brings the supervisor back.
     - **Limits.** Detection needs OpenBao (unsealed) and the reconciler: a revoked role can still log in until the reconciler's next pass plus the watcher's interval (lab up to about 17 s; with the production proposal of 60 s, up to about 62 s). A lease whose username was generated more than 3 s before it was issued would not be matched. The volume is a single-host channel: with replicas on other hosts the descriptors need a transport of their own (not built). With several PostgreSQL OpenBao roles, list each in both `PG_DENY_ROLES` and `PG_DENY_ALLOWED_ROLES`.
  - Measured (lab, `tests\revocation-checks.ps1` section 3, primary outages of about 180 s, two runs): the revoked role was refused on `pg-replica` 11.0 s and 12.7 s after the revoke (descriptor written +9.6 s / +10.4 s, watcher deny +11.1 s / +12.3 s) and never logged in again during the outage (332 and 321 later attempts); its open session was terminated +11.4 s / +12.5 s; the still-valid role of another second kept working (31/31, 34/34 logins, its session stayed); the still-valid role of the same second was refused too (over-deny, 8/8 and 7/7). Bound: one reconciler interval plus one watcher interval. A `pg-replica` restart during the outage wrote the deny list 1.2 s / 1.1 s after the restart command, about 0.5 s before the first accepted login: 0 of 13 and 0 of 12 revoked-role attempts in that window succeeded. kill -9 of the watcher: restarted after about 1 s, no crash-restart. After the primary returned: role dropped on the replica 9.6 s / 12.7 s, descriptor removed 21.9 s / 26.6 s, deny list back to the sentinel 82.7 s / 88.5 s after the start command (the over-denied role held for the 60 s grace). Idle: no watcher line and no watcher login in 20 s. The former measurement was 10 of 10 logins during a 150 s outage, bounded only by `VALID UNTIL`.
  - The stale-user detector still reports leftovers after `max_ttl` + margin: `scripts\phase3-stale-users.ps1 -ComposeFile .\compose.phase4.yaml -Project security-prototype-phase4 -MariaHost maria-replica`.
  - With several replicas, each needs its own OpenBao connection and role (a temp user exists only on the replica it was created on). Not built.
- MariaDB passwords set on the primary (`config/mariadb/phase4/`: `10-app1-users.sh`, `20-replication.sh`, `phase2-access-setup.sh`, `phase3-access-setup.sh`, mounted at the same paths as the shared originals): every account is created `ACCOUNT LOCK` without a password, gets it with `SET PASSWORD FOR ... = PASSWORD('<pw>')` and is unlocked. Measured on 11.8: the binlog keeps `CREATE/ALTER USER ... IDENTIFIED BY`, `IDENTIFIED VIA mysql_native_password USING PASSWORD(...)`, `GRANT ... IDENTIFIED BY` and even `CREATE USER IF NOT EXISTS ... IDENTIFIED BY` for an existing account in clear text; `SET PASSWORD FOR` and `IDENTIFIED BY PASSWORD '<hash>'` only as the hash. The bao_admin initial password is set only when the account is new (the shared script re-sent it on every run). The replicator password stays in the replica's `master.info` (configuration, not a log).
- The replica's seed (`config/mariadb/phase4/20-replica-seed.sh`) loads the dump with `sql_log_bin = 0` and with `server_audit_logging` switched OFF around the load (in the image's network-less init server), so the `INSERT INTO global_priv` with every account's password hash is no longer in the replica's audit log or the store. The `SET GLOBAL server_audit_logging = OFF` / `ON` statements themselves are audited.

Normalized record fields: `timestamp` (source time, UTC), `source` (`pg-primary`, `pg-replica`, `maria-primary`, `maria-replica`, `openbao`, `pg-sweeper`, `maria-sweeper`, `lease-reconciler`), `engine` (`postgresql`, `mariadb`, `openbao`, `sweeper`, `backstop`, `reconciler`), `user` (OpenBao: the person), `client_host`, `event` (`login`, `login_failed`, `logout`, `audit`, `query`, `error`, OpenBao `request`/`response`, the sweeper, backstop or reconciler action, ...), `statement`, plus engine fields (`session_id`, `state_code`, `audit_class`; `connection_id`, `retcode`; `lease_id`, `db_username`, `path`, `error`; backstop `dropped`, `users`; reconciler `lease_id`, `role`, `outcome`, `detail`; PostgreSQL deny-list watcher (source `pg-replica`, engine `backstop`, `target_engine` `postgresql`) `descriptor`, `issued`, `users`, `matched`, `terminated`, `over_deny`, `reason`, `pattern`, `receiver`). The `init_file` statements appear in the replica's `server_audit` log with user `boot`. The image healthchecks' routine connect/disconnect records are not shipped (about 100,000 lines a day per server); they stay in the source logs.

Alert rules (lab form, `audit.lua`):

- `login_not_allowlisted`: a successful login by an account that is not a temp user (`v-...`) and not one of: PostgreSQL `app1_runtime`, `app1_migrator`, `bao_admin`, `session_sweeper`, `replicator`, `postgres`; MariaDB the same plus `healthcheck` and `root`.
- `superuser_login`: any login or login attempt of `postgres` or MariaDB `root`, local or over the network. Only exception: the PostgreSQL image healthcheck (local socket and `application_name=pg-healthcheck`, which a local superuser could also set).
- `temp_user_denied`: a temp user's statement refused by a privilege check (PostgreSQL SQLSTATE 42501, MariaDB access-denied codes). `temp_user_write`: a temp user's statement that tries to write or change anything, whatever the outcome.
- `openbao_request_failed`: an OpenBao response with an error, as a stand-in for "audit device failure" (a failed audit device cannot be seen in its own log).
- `replica_startup_purge`: `maria-replica` dropped one or more `v-` users at startup (users left behind by a revocation that could not reach the replica, or of still-valid leases).
- `replica_expiry_backstop`: the replica's event dropped `v-` users older than `max_ttl` + margin (OpenBao failed to revoke them).
- `irrevocable_lease_found`: the lease reconciler found an irrevocable database lease.
- `revocation_retried_by_reconciler`: the reconciler re-revoked a pending or irrevocable lease (every attempt, `outcome=ok` or `failed`).
- `pg_replica_deny_applied`: `pg-replica` now refuses the temp role(s) of a lease whose revocation is pending or irrevocable (the primary is unreachable); `users` names them, `terminated` counts the sessions ended, `over_deny=1` means more than one role matched.
- `pg_deny_descriptor_rejected`: a file in the descriptor volume failed validation (only the reconciler can write there: a bug or a compromised reconciler).
- `pg_deny_watcher_failed`: the deny-list watcher exited and was restarted, its supervisor was stopped, the descriptor directory is unreadable, or a rewrite or reload failed.
- `pg_server_process_crashed`: the postmaster saw a child process die abnormally and restarted every session (for example SIGKILL of the watcher's supervisor).
- Not built (out of scope): bulk export / large result sets, break-glass reads, auditd and Docker events.

Passwords in logs, as measured by `tests\phase4-checks.ps1`:

- pgAudit 17.1 itself writes `PASSWORD <REDACTED>` for `CREATE/ALTER ROLE`, with or without OpenBao's `password_authentication=scram-sha-256`. PostgreSQL's own statement logging (`log_statement`, and the `STATEMENT` of a failed statement) writes the statement verbatim: with `password_authentication=password` that is the clear-text temp password, with `scram-sha-256` only the SCRAM verifier. Keep `scram-sha-256`.
- `server_audit` masks `IDENTIFIED BY *****` and `PASSWORD(*****)`. The MariaDB binary log does not, which in phases 2 and 3 put every temp password and every long-lived password set with `IDENTIFIED BY` into the primary's binlog and the replica's relay log. In phase 4 (see above) no MariaDB password is in any binary log, relay log, audit log or the store; `tests\phase4-checks.ps1` searches all of them (and both data directories, `docker logs` and the store) for every temp password it generates and every MariaDB secret. The only clear-text MariaDB password in a data directory is the replicator's in the replica's `master.info`.
- Failed logins never log the attempted password.

Passwords already in the binlogs of an existing server (production remediation; `tests\phase4-checks.ps1 -LeakAndPurgeTest` runs it in the lab): switch the account scripts and OpenBao to the forms above, rotate every affected password with a hash-only statement (`SET PASSWORD FOR`, OpenBao `rotate-root`), then `FLUSH BINARY LOGS` on the primary, wait until every replica has applied everything (`MASTER_GTID_WAIT`), `PURGE BINARY LOGS TO '<current file>'` on the primary, and on each replica `FLUSH RELAY LOGS` (applied relay logs are deleted by `relay_log_purge`) and, if it has a binlog, `FLUSH BINARY LOGS` and `PURGE BINARY LOGS TO '<current file>'`. Backups and binlog archives taken before that still hold the old passwords; the rotation is what makes them worthless.

LAB-ONLY, in addition to the phase 3 list: the phase 4 OpenBao instance keeps its unseal key and root token in `secrets\openbao_phase4_unseal_key` and `secrets\openbao_phase4_root_token`; the lease reconciler's AppRole role ID and secret ID are plain files `secrets\openbao_phase4_reconciler_role_id` / `_secret_id` with a secret ID that never expires (production: deliver a response-wrapped secret ID with a short TTL and `secret_id_num_uses`, rotated by the orchestrator, or use a platform identity such as Kubernetes or cert auth instead of a stored secret ID); the store has no rotation or retention, and the backstop log directory gets one small file per replica start and per backstop run that dropped users; `tests\phase4-checks.ps1` writes one revoked PostgreSQL temp password to the logs and the store in clear text on purpose (PostgreSQL leak reproduction, case B). It writes no MariaDB clear text, except with `-LeakAndPurgeTest`, which reproduces the old MariaDB leaks and then purges all older binlogs of both MariaDB servers.

### Start and set up

```powershell
docker compose -f compose.phase3.yaml down
powershell -ExecutionPolicy Bypass -File .\scripts\gen-secrets.ps1
docker compose -f compose.phase4.yaml up -d --build
powershell -ExecutionPolicy Bypass -File .\scripts\phase4-setup.ps1
```

`phase4-setup.ps1` runs `phase3-setup.ps1` (and with it `phase2-setup.ps1`, both with `-MariaTempUsersOnReplica` and the hash-only MariaDB rotation statement) against the phase 4 stack, then sets the MariaDB root rotation statement and rotates, creates or checks `bao_replica_admin` on the replica and the OpenBao connection `app1-maria-replica` (initial password and rotation only when the account is new or OpenBao can no longer connect), points `app1-maria-ro` at it, re-applies the pgAudit role settings, checks the replica's backstop event (enabled, own definer) and shows its last startup purge, sets up the lease reconciler (auth method `approle`, policy `lease-reconciler`, role `lease-reconciler`, a new secret ID written to `secrets\openbao_phase4_reconciler_*`, older secret IDs destroyed, `lease-reconciler` recreated and waited for until it logs `action=ready`), checks the PostgreSQL replica deny list (the `app1-pg` username template is the one the watcher expects, watcher and supervisor running in `pg-replica`, descriptor volume `100:1000 0755`, `pg_hba` line 2 loaded), and shows that the audit plugins are loaded and the store is being written. It is idempotent. `gen-secrets.ps1` now also writes the two reconciler placeholder files (it keeps existing ones); they must exist before the first `up`.

### Test

```powershell
powershell -ExecutionPolicy Bypass -File .\tests\smoke.ps1 -Phase 1
powershell -ExecutionPolicy Bypass -File .\tests\phase1-checks.ps1 -ComposeFile .\compose.phase4.yaml -Project security-prototype-phase4
powershell -ExecutionPolicy Bypass -File .\tests\phase2-checks.ps1 -ComposeFile .\compose.phase4.yaml -Project security-prototype-phase4 -BaoSecretPrefix openbao_phase4 -PgDevHost pg-replica -MariaDevHost maria-replica -MariaTempUsersOnReplica
powershell -ExecutionPolicy Bypass -File .\tests\phase3-checks.ps1 -ComposeFile .\compose.phase4.yaml -Project security-prototype-phase4 -BaoSecretPrefix openbao_phase4 -MariaTempUsersOnReplica
powershell -ExecutionPolicy Bypass -File .\tests\phase4-checks.ps1
powershell -ExecutionPolicy Bypass -File .\tests\revocation-checks.ps1
# optional, about 13 minutes more: a real irrevocable lease
powershell -ExecutionPolicy Bypass -File .\tests\revocation-checks.ps1 -IrrevocableTest
```

`revocation-checks.ps1` (about 10 minutes; parameters `-ComposeFile`, `-Project`, `-BaoSecretPrefix` with the phase 4 defaults) tests the three revocation backstops alone and together: the replica configuration (`init_file`, event, definer privileges, replicated events `SLAVESIDE_DISABLED`, the reconciler's network); the startup purge with a login poller in `maria-sweeper`'s network namespace (about 20 ms per attempt) started before `docker compose start maria-replica`, comparing every answer with the purge's completion time; the still-valid user dropped by a plain restart and its lease still revocable; the expiry backstop with a backdated lab `v-` user (hash-only password, `sql_log_bin = 0`), its session, a fresh user, an unparseable `v-` name and a non-`v-` account; each definer privilege removed one at a time; the reconciler completing revocations queued during an outage (at least 150 s) of `maria-replica` and `pg-primary`; during that outage the PostgreSQL deny list, timed with a login poller on the access network (revoked role, a still-valid role of another second, a still-valid role issued in the same second): refusal and session termination of the revoked role, the still-valid role unaffected, the same-second role over-denied, the alert, kill -9 of the watcher (restarted, no crash-restart), SIGTERM of its supervisor (alerted, deny list stays in effect), a `pg-replica` restart without a login window; after the primary returns, descriptor and entry pruned and the deny list back to the sentinel; 23 malicious descriptors written with the reconciler's uid and mount (quotes, newlines, `all`, `+group`, `@file`, `replicator`, `bao_admin`, `postgres`, path traversal, symlink, oversized, comma, NUL, MariaDB role, future time, name/body mismatch, FIFO, directory, space, regex, CRLF, leading zero, no extension) rejected and alerted with `pg_hba` unchanged; the channel's mounts and ownership; the entrypoint step without the descriptor directory; no watcher activity while idle; the reconciler token's refusals, its CIDR binding, each policy rule removed one at a time, and its credentials absent from logs, process listing and the store; the shipped records and the alerts. It stops and starts `maria-replica` three times and `pg-primary` once, restarts `pg-replica` once and pauses `lease-reconciler` briefly. This replaces the former "PostgreSQL EXPOSURE" measurement (the revoked role logged in 10 of 10 times during a 150 s primary outage). `-IrrevocableTest` keeps `maria-replica` down until OpenBao marks a lease irrevocable (about 11 minutes), then shows detection, alert and revocation after the restart.

Since the revocation backstops, the phase 3 and phase 4 suites expect the new behaviour (printed as `ALTERED` lines): after a replica restart the revoked MariaDB user is already gone and its login refused (formerly a measured login gap), the lease then disappears (OpenBao retry or reconciler), the user of a failed `-sync` revoke is gone too (its lease keeps its TTL), MariaDB temp users issued before a replica restart are re-issued for later checks, the refusal may be `1130 Host ... is not allowed to connect` when no account matches the client any more, and the replica-only account `revocation_backstop` is left out of the primary/replica account comparison.

`-MariaTempUsersOnReplica` tells the phase 2 and 3 checks that the MariaDB temp users live on the replica: the MariaDB facts they read on the primary are read on the replica, the "killed by the sweeper" and "session survives revocation without the sweeper" expectations become "killed by the revocation statement", and the revoke-while-the-replica-is-down check waits for OpenBao's retry. Every altered assertion prints an `ALTERED` line with its reason. Without the switch the phase 2 and 3 suites behave as before.

`phase4-checks.ps1` takes about five minutes (`phase3-checks.ps1` about four). It issues temp users as `alice`, runs masked-view queries, denied queries and writes on both replicas and waits (bounded) for the records and alerts in the store; prints the join person -> lease -> username -> query; logs in with a throwaway account `lab_rogue` and as `postgres`/`root`; searches every log volume, the data directories (WAL, binlogs, relay log, master.info), `docker logs` and the store for the generated passwords and the MariaDB secrets inside throwaway containers (only counts and file names are printed); reproduces the PostgreSQL leak without `scram-sha-256` and shows the mitigation; checks the MariaDB replica path (network, OpenBao configuration, `bao_replica_admin` privileges one by one, the `sql_log_bin` guard, logins of `bao_replica_admin` to the replica and the primary, 20 temp users of churn with replication health, revocation with and without the sweeper, revoke while `maria-replica` is stopped, revocation of a user a re-seed removed, no seed hashes in the audit log); checks mounts, ownership and the tamper limits; and prints shipping latency, credential and revocation times, bytes per query and per application request, and memory. It stops and starts `maria-sweeper` and `maria-replica` once each.

`tests\phase4-checks.ps1 -LeakAndPurgeTest` additionally reproduces the old MariaDB leaks (a `CREATE USER ... IDENTIFIED BY` on the primary, the phase 2/3 `bao_admin` rotation statement), then rotates and runs `PURGE BINARY LOGS` on both servers and shows that the clear text is gone. It deletes all older binlogs, so run it only when they need not be inspected any more.

### Read the shipped audit log and the alerts by hand

The `fluent-bit` image has no shell, so read the store with a throwaway container that mounts the volume read-only (no network). Avoid double quotes in the arguments: Windows PowerShell 5.1 drops them when it calls `docker`.

```powershell
# the latest alerts
docker run --rm --network none -v security-prototype-phase4_log-store:/store:ro postgres:17 tail -n 20 /store/alerts.jsonl
# everything a person's temp users did (logins, statements, logouts, the OpenBao responses), on every server
docker run --rm --network none -v security-prototype-phase4_log-store:/store:ro postgres:17 grep -F v-oidc-alice- /store/audit.jsonl
# readable in PowerShell
docker run --rm --network none -v security-prototype-phase4_log-store:/store:ro postgres:17 tail -n 200 /store/audit.jsonl | ForEach-Object { $_ | ConvertFrom-Json } | Where-Object { $_.user -like 'v-*' } | Format-Table timestamp, source, event, user, client_host, statement -AutoSize -Wrap
```

To map a database username to a person, find the OpenBao response that created it: the record with `"source":"openbao"`, `"event":"response"` and `"db_username":"<username>"` has `user` (the person), `display_name`, `entity_id` and `lease_id`. Search for the username alone; both records contain it.

The source logs are on the volumes `security-prototype-phase4_pg-primary-log`, `_pg-replica-log` (the deny-list watcher in its subdirectory `pg-deny/`), `_maria-primary-audit`, `_maria-replica-audit`, `_bao-audit`, `_pg-sweeper-log`, `_maria-sweeper-log` and `_reconciler-log`; mount them read-only the same way. The current deny list: `docker compose -f compose.phase4.yaml exec pg-replica cat /var/lib/postgresql/pg-deny/denied_roles`; the descriptors: `docker compose -f compose.phase4.yaml exec lease-reconciler ls -l /pg-deny`.

The MariaDB binary logs are in the data volumes (`_maria-data`: `mariadb-bin.*`; `_maria-replica-data`: `maria-replica-bin.*` and `maria-replica-relay.*`). To look at them by hand, decoded, without starting a server:

```powershell
docker run --rm --network none -v security-prototype-phase4_maria-data:/m:ro --entrypoint sh mariadb:11.8 -c 'mariadb-binlog /m/mariadb-bin.0* | grep -aiE ''password|create user'' | head -n 40'
```

### What a superuser can still do

Auditing is a detection control. On PostgreSQL a superuser can `SET pgaudit.log = 'none'` in a session, `ALTER ROLE ... SET pgaudit.log` for any role, or restart the server with other options (`ALTER SYSTEM` does not override the command line). On MariaDB root can `SET GLOBAL server_audit_logging = OFF` (tested: the OFF and the ON statement are logged, the statements in between are not) or change `server_audit_excl_users` / `server_audit_events` at runtime (not tested). Anyone with root on the host or `docker exec` into a database container can change or delete the source logs before they are shipped; the store is out of their reach only as long as they cannot reach the Docker host. A temp user cannot change any `pgaudit.*` or `server_audit_*` setting (tested). Every `postgres` and `root` login raises `superuser_login`.

### Unseal after a restart

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\phase2-unseal.ps1 -ComposeFile .\compose.phase4.yaml -Project security-prototype-phase4 -BaoSecretPrefix openbao_phase4
```

After editing a file under `config\` (including `config\fluent-bit\`), run `docker compose -f compose.phase4.yaml up -d --force-recreate <service>`. After an OpenBao restart the lease reconciler logs `action=error` (sealed) and `action=recovered` once OpenBao is unsealed again. Fluent Bit keeps its read positions in the `fluent-bit-state` volume, so a recreated shipper does not ship records twice.

### Stop and wipe

```powershell
docker compose -f compose.phase4.yaml down -v
Remove-Item .\secrets\openbao_phase4_unseal_key, .\secrets\openbao_phase4_root_token
```

`-v` also deletes the log volumes and the store. Keep `secrets\openbao_phase4_reconciler_role_id` and `_secret_id`: they are worthless after the wipe (the next `phase4-setup.ps1` replaces them), but if they are missing at `up`, Docker creates directories in their place. If you deleted them, run `gen-secrets.ps1` before `up`.

## Memory on an 8 GB host

Cap WSL2 at about 5 GB in `%UserProfile%\.wslconfig`, then run `wsl --shutdown` and restart Docker Desktop:

```ini
[wsl2]
memory=5GB
```
