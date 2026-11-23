# Production Database Access Hardening: Findings and Prototype Plan

Date: 2026-11-16
Scope: Developers of internal tools need to debug production data. Databases: **PostgreSQL** and **MariaDB**. Organization has **100+ personnel**. Requirement: **free and self-hosted**.

---

## 1. Principles

Developers should almost never touch production directly. When they do, access should be **temporary, read-only, per-person, logged, and limited to the data needed**.

1. **Remove the need first**
   - Structured logs, tracing, error tracking (e.g. Sentry).
   - Staging with anonymized or masked copies of production data.
   - Admin/support screens in the internal tools for recurring lookups.
2. **Grant access just in time**
   - Request with a reason (ticket ID), approval, automatic expiry (1-4 h).
   - No permanent production credentials for anyone.
3. **Read-only by default, on a read replica**
   - A heavy query must not hurt the primary.
   - Write access is a separate, rarer request with stronger approval.
4. **Per-person identity**
   - SSO (Keycloak / Entra ID). No shared logins, never the app's service account.
5. **No direct network exposure**
   - VPN (WireGuard / Headscale), bastion, or an access gateway.
6. **Mask sensitive data**
   - Views or column-level grants over PII / payment data. OpenBao does *not* mask data itself.
7. **Audit everything**
   - Per-user query logs shipped to a store developers cannot edit or delete.
   - Review access regularly, alert on bulk exports.
8. **Data fixes go through code review**
   - Reviewed script or migration, run by a pipeline or second person, in a transaction, tested on staging, with a backup of the affected rows.

GDPR angle (EU): data minimization means masking by default; audit logs show who accessed personal data and why.

---

## 2. Why not Teleport

Teleport is an access gateway (SSH, Kubernetes, databases, web apps) using short-lived certificates, SSO, RBAC and session recording.

**Not viable here.** Since Teleport 16, the official binaries and images use a commercial license. Community Edition is free only for organizations with **< 100 employees and < US $10M annual revenue**. Building from source gives AGPLv3, but you take on compiling and distributing it yourself. With 100+ personnel a paid license would be required.

---

## 3. Free, self-hosted options

**Note:** Only the Teleport licensing was checked against sources in this session. The tools below come from general knowledge. **Verify license terms, features and user limits before committing** (this matters especially for hoop.dev and Bytebase, whose free tiers can change).

| Tool | Role | Notes |
|---|---|---|
| **OpenBao** (MPL 2.0, Vault fork) | Issues short-lived DB credentials | Database secrets engine creates a temp user with a TTL and drops it automatically. Supports PostgreSQL, MySQL/MariaDB and others. Audit log, OIDC login. |
| **Keycloak** | SSO / identity provider | Or use Entra ID if already in place. Group membership drives OpenBao policies. |
| **Warpgate** (Apache 2.0) | Lightweight bastion with session recording | SSH, HTTP, MySQL, PostgreSQL. Closest simple match to a gateway. |
| **hoop.dev** | Access gateway with approvals, masking, audit | Open-source core. Verify which features are free. |
| **JumpServer** (GPLv3) | Full PAM suite with web UI | Heavier to run. |
| **Bytebase** (community) | Web SQL client with review, masking, audit | Check user limits in the free tier. |
| **pgAudit / MariaDB audit plugin** | In-database query logging | Gives per-user logs because each temp user name encodes who requested it. |
| **WireGuard / Headscale** | Private network access | Keeps databases off the public internet. |

### Should we build our own access broker?

**Usually no.** A custom broker means writing security-critical software (credential issuing, revocation, audit integrity) that must be maintained for years. Instead:

- Use **OpenBao for credential issuing**: keep the security logic there.
- Build only a **thin internal portal** (C# + Angular fits the existing stack): developer picks app + environment, enters a ticket ID, a lead approves, the portal calls OpenBao's API to issue credentials. A few hundred lines of glue.
- Build more only if a hard requirement (unusual database, compliance workflow) rules out existing tools.

---

## 4. Recommended architecture

```
Developer ──VPN──► (optional gateway: Warpgate / hoop.dev, session recording)
     │
     ├─ SSO login (Keycloak / Entra ID, OIDC) ──► OpenBao
     │                                              │  policy by SSO group
     │                                              ▼
     │                              database secrets engine
     │                       (creates temp user on the PRIMARY, TTL 1-4 h)
     │                                              │
     └──────────── connects with temp user ────────► READ REPLICA
                                                    │
                          pgAudit / MariaDB audit ──► append-only log store
```

Optional: internal approval portal sits in front of the "read credentials" step.

### Important: where OpenBao connects

OpenBao must connect to the **primary**, not the replica. Creating users on a hot standby fails in PostgreSQL, and on a MariaDB replica it would diverge from replication. The temp user is created on the primary and **replicates to the read replica**, where the developer then connects.

Consequences:
- Replication lag means new credentials may take a moment to work on the replica. Handle with a retry, or a short wait in the portal.
- Revocation (`DROP USER`) also replicates, so it is not instant on the replica. Keep TTLs short.

---

## 5. Configuration (one app, one PostgreSQL + one MariaDB)

CLI is `bao`. Names (`app1`, `debug_ro`, hosts) are placeholders.

### 5.1 One-time setup in each database

PostgreSQL (run on the **primary**):

```sql
CREATE ROLE debug_ro NOLOGIN;
GRANT CONNECT ON DATABASE app1 TO debug_ro;
GRANT USAGE ON SCHEMA public TO debug_ro;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO debug_ro;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO debug_ro;

CREATE ROLE bao_admin LOGIN CREATEROLE PASSWORD '...';
GRANT debug_ro TO bao_admin WITH ADMIN OPTION;  -- needed on PostgreSQL 16+
```

MariaDB (run on the **primary**):

```sql
CREATE ROLE debug_ro;
GRANT SELECT ON app1.* TO debug_ro;

CREATE USER 'bao_admin'@'%' IDENTIFIED BY '...';
GRANT CREATE USER ON *.* TO 'bao_admin'@'%';
GRANT debug_ro TO 'bao_admin'@'%' WITH ADMIN OPTION;
```

The permissions live in the database role (`debug_ro`). OpenBao only creates and drops users. To hide PII, grant `debug_ro` access to **masked views** instead of base tables.

### 5.2 Connect OpenBao to the databases

```bash
bao secrets enable database

bao write database/config/app1-pg \
  plugin_name=postgresql-database-plugin \
  connection_url="postgresql://{{username}}:{{password}}@pg-primary:5432/app1" \
  username=bao_admin password=... \
  allowed_roles=app1-pg-ro

bao write database/config/app1-maria \
  plugin_name=mysql-database-plugin \
  connection_url="{{username}}:{{password}}@tcp(maria-primary:3306)/" \
  username=bao_admin password=... \
  allowed_roles=app1-maria-ro

# After this, only OpenBao knows the admin password
bao write -force database/rotate-root/app1-pg
bao write -force database/rotate-root/app1-maria
```

MariaDB uses the MySQL plugin.

### 5.3 Temporary-access roles

```bash
bao write database/roles/app1-pg-ro db_name=app1-pg \
  default_ttl=1h max_ttl=4h \
  creation_statements="CREATE ROLE \"{{name}}\" LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT debug_ro TO \"{{name}}\";" \
  revocation_statements="DROP ROLE IF EXISTS \"{{name}}\";"

bao write database/roles/app1-maria-ro db_name=app1-maria \
  default_ttl=1h max_ttl=4h \
  creation_statements="CREATE USER '{{name}}'@'%' IDENTIFIED BY '{{password}}'; GRANT debug_ro TO '{{name}}'@'%'; SET DEFAULT ROLE debug_ro FOR '{{name}}'@'%';" \
  revocation_statements="DROP USER '{{name}}'@'%';"
```

PostgreSQL gets a built-in expiry backstop (`VALID UNTIL`). MariaDB has no equivalent here, so also plan a **periodic cleanup job** that drops stale temp users (see open questions).

### 5.4 Who may request credentials

```hcl
# policy: app1-debug.hcl
path "database/creds/app1-pg-ro"    { capabilities = ["read"] }
path "database/creds/app1-maria-ro" { capabilities = ["read"] }
```

Attach the policy to an SSO group (e.g. `app1-devs`) via OIDC auth (Keycloak / Entra ID). Enable auditing:

```bash
bao audit enable file file_path=/var/log/bao/audit.log
```

### 5.5 Developer workflow

```bash
bao login -method=oidc
bao read database/creds/app1-pg-ro
# username v-oidc-jdoe-app1-pg-ro-x8f2..., password, lease 1h
```

At TTL expiry OpenBao drops the user. Early revoke: `bao lease revoke <lease_id>`.

---

## 6. Gotchas

- **Keep temp users read-only.** A user that creates objects (e.g. tables in PostgreSQL) cannot be dropped cleanly.
- **Approvals are not built into OpenBao.** That is the job of the portal (or hoop.dev / Teleport-like tools).
- **OpenBao does not mask data.** Use views / column grants.
- **Gateway and OpenBao integration is not automatic.** Warpgate has its own users and targets. Decide in the prototype whether developers connect directly with OpenBao credentials over VPN, or through the gateway.
- **Audit log integrity:** ship OpenBao and database audit logs off-box to storage developers cannot modify.
- **OpenBao itself is now critical infrastructure:** plan unsealing, HA / backup, and who holds the root/recovery keys.
- Usernames include who requested them, so database logs map queries to a person.

---

## 7. Prototype plan

Goal: prove the temp-credential flow end to end on disposable infrastructure.

**Stack (Docker Compose):**
- OpenBao (dev mode first, then real storage + unseal)
- PostgreSQL primary + streaming replica
- MariaDB primary + replica
- Keycloak with a test realm and an `app1-devs` group

**Steps:**
1. Compose file with PostgreSQL and MariaDB primaries + replicas, seeded with a sample schema containing a fake PII column.
2. Apply section 5.1 (roles, admin users, masked view for PII).
3. Run OpenBao, configure sections 5.2-5.3.
4. Add Keycloak OIDC auth to OpenBao, map group `app1-devs` to the policy from 5.4.
5. Verify as a test developer:
   - credentials issue, login works **on the replica** (check replication lag),
   - `INSERT`/`UPDATE`/`DELETE` fail,
   - PII is masked,
   - user disappears after TTL,
   - early `lease revoke` works.
6. Enable pgAudit and the MariaDB audit plugin, confirm queries map to the named user.
7. Optional: thin portal (C# API + Angular) with ticket ID + approval step calling OpenBao.
8. Optional: put Warpgate in front and compare to direct VPN access.

**Open questions for the prototype:**
- Replication lag impact on first connection, and behavior when the replica is behind during revocation.
- MariaDB expiry backstop (no `VALID UNTIL` equivalent): cleanup job vs. relying on OpenBao leases only.
- Does the real PostgreSQL / MariaDB version need adjustments to the grant syntax (role admin option, default roles)?
- How many databases / apps need roles, and how to template role creation.
- Which approval mechanism: custom portal vs. an existing tool.
- Can all production audit logs be shipped off-box with existing log infrastructure?

---

## 8. Sources

- Teleport Community Edition license change (v16): https://goteleport.com/blog/teleport-community-license
- Teleport license text: https://scancode-licensedb.aboutcode.org/teleport-ce-2024.LICENSE
- Teleport feature matrix: https://goteleport.com/docs/feature-matrix/
