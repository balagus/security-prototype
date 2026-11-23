#!/bin/bash
# Phase 3: replica session sweeper account (design 5.1 / 5.4, PostgreSQL). Run on the PRIMARY
# by scripts/phase3-setup.ps1 after phase2-access-setup.sh, as OS user postgres over the local
# socket:  docker exec -u postgres <pg-primary> bash /opt/phase3/access-setup.sh
# The role replicates to pg-replica, where pg-sweeper uses it. pg_hba.conf allows it only on
# the replica and only from the sweeper's fixed address; the primary rejects it.
# Idempotent: the password is re-set from the Docker secret on every run.
#
# Least privilege, measured (tests\phase3-checks.ps1):
#   pg_signal_backend   needed: pg_terminate_backend() on other roles' sessions.
#   pg_read_all_stats   NOT needed, and deliberately not granted: pid and usesysid of every
#                       session are visible in pg_stat_activity to any role, and that is all the
#                       sweeper uses. Without it backend_type, backend_start, state, query and
#                       client_addr of other roles' sessions read as NULL, so a sweeper query
#                       that filters on backend_type or backend_start (as in the first design
#                       draft) silently matches nothing. Granting it would also let the sweeper
#                       read every session's query text.
#   CONNECT on app1     needed because CONNECT is revoked from PUBLIC (phase 1).
set -euo pipefail

psql -v ON_ERROR_STOP=1 -X -q --no-psqlrc -d app1 <<'SQL'
\set sweeper_pw `cat /run/secrets/pg_session_sweeper_password`
SELECT NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'session_sweeper') AS need_sweeper \gset
\if :need_sweeper
CREATE ROLE session_sweeper LOGIN;
\endif
ALTER ROLE session_sweeper LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
  CONNECTION LIMIT 2 PASSWORD :'sweeper_pw';
\unset sweeper_pw
GRANT pg_signal_backend TO session_sweeper;
GRANT CONNECT ON DATABASE app1 TO session_sweeper;
ALTER ROLE session_sweeper SET statement_timeout = '10s';
SQL

psql -X -At --no-psqlrc -d app1 -c "SELECT 'phase3-access-setup (pg): ok; session_sweeper member of: ' || coalesce((SELECT string_agg(b.rolname, ',') FROM pg_auth_members m JOIN pg_roles b ON b.oid = m.roleid JOIN pg_roles r ON r.oid = m.member WHERE r.rolname = 'session_sweeper'), '-')"
