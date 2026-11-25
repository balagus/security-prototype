#!/bin/bash
# Per-role pgAudit settings (compose.yaml, pg-primary). Mounted twice:
#   - as /docker-entrypoint-initdb.d/05-pgaudit-roles.sh: first init, BEFORE 10-app1-roles.sh
#     and 20-replication.sh, so the superuser's own statements are audited from the start;
#   - as /opt/setup/audit-roles.sh: run again by scripts/setup-audit.ps1 after the sweeper
#     account exists:  docker exec -u postgres <pg-primary> bash /opt/setup/audit-roles.sh
# Idempotent. Role settings live in the catalog, so they replicate to pg-replica.
#
# The server-wide settings (command line in compose.yaml) apply to every role without a
# role setting. Temporary users and debug_ro have NO role setting on purpose: a setting on
# debug_ro would not reach its members, so the server-wide value is what audits them.
#
#   postgres         read, write, ddl, role, misc_set; no catalog-only statements.
#                    The role class is safe here although the init and setup scripts set app,
#                    replicator and sweeper passwords as postgres (CREATE/ALTER ROLE ...
#                    PASSWORD): pgAudit 17.1 writes "PASSWORD <REDACTED>" and drops the rest
#                    of such a statement (tested for CREATE ROLE/USER, ALTER ROLE/USER, WITH,
#                    ENCRYPTED, options before and after PASSWORD). Core statement logging
#                    (log_statement) would NOT redact; it stays off. Every postgres login is
#                    also logged (log_connections) and raises an alert in the shipper.
#                    log_catalog off: the replica healthcheck and test polls query pg_catalog
#                    every few seconds.
#   session_sweeper  catalog-only statements not logged (it polls pg_stat_activity/pg_roles
#                    every interval); anything else it ran would still be logged.
# The entrypoint sources this file when it is not executable, so no "set -u" and no "exit".
set -eo pipefail

psql -v ON_ERROR_STOP=1 -X -q --no-psqlrc --username postgres --dbname postgres <<'SQL'
ALTER ROLE postgres SET pgaudit.log = 'read, write, ddl, role, misc_set';
ALTER ROLE postgres SET pgaudit.log_catalog = off;
SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'session_sweeper') AS have_sweeper \gset
\if :have_sweeper
ALTER ROLE session_sweeper SET pgaudit.log_catalog = off;
\endif
SQL

psql -X -At --no-psqlrc --username postgres --dbname postgres -c "SELECT 'audit-roles (pg): ' || coalesce(string_agg(r.rolname || ' {' || array_to_string(s.setconfig, ', ') || '}', '; ' ORDER BY r.rolname), 'none') FROM pg_db_role_setting s JOIN pg_roles r ON r.oid = s.setrole WHERE s.setdatabase = 0 AND r.rolname IN ('postgres', 'session_sweeper')"
