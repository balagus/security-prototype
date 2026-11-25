#!/bin/bash
# Database side of developer just-in-time access (docs/DECISIONS.md D5, PostgreSQL).
# NOT a first-init script: the masked views need the tables that dotnet-migrate creates, so
# scripts/setup-access.ps1 runs this after the migrations, as OS user postgres over the local
# socket (peer auth):  docker exec -u postgres <pg-primary> bash /opt/setup/access-setup.sh
# Idempotent. It never changes the bao_admin password once the role exists, because OpenBao
# rotates it (rotate-root) and is then the only holder.
# The initial bao_admin password is read by psql itself from the Docker secret (\set with
# backticks), so it never appears on a command line.
set -euo pipefail

psql_app1() { psql -v ON_ERROR_STOP=1 -X -q --no-psqlrc -d app1 "$@"; }

ready="$(psql_app1 -At -c "SELECT (to_regclass('public.customers') IS NOT NULL AND to_regclass('public.orders') IS NOT NULL)::text")"
if [ "$ready" != "true" ]; then
    echo "access-setup (pg): tables public.customers/public.orders do not exist yet; run the migrations first" >&2
    exit 1
fi

psql_app1 <<'SQL'
\set bao_pw `cat /run/secrets/pg_bao_admin_initial_password`

-- Roles (created once; attributes re-asserted on every run).
SELECT NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'view_owner') AS need_view_owner,
       NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'debug_ro')   AS need_debug_ro,
       NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'bao_admin')  AS need_bao_admin \gset
\if :need_view_owner
CREATE ROLE view_owner NOLOGIN;
\endif
\if :need_debug_ro
CREATE ROLE debug_ro NOLOGIN;
\endif
\if :need_bao_admin
CREATE ROLE bao_admin LOGIN CREATEROLE PASSWORD :'bao_pw';
\endif
\unset bao_pw
ALTER ROLE view_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE debug_ro   NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE bao_admin  LOGIN CREATEROLE NOSUPERUSER NOCREATEDB NOREPLICATION NOBYPASSRLS;

-- Masked surface: developers see only schema "debug". Explicit allow-list of base tables.
GRANT USAGE ON SCHEMA public TO view_owner;
GRANT SELECT ON public.customers, public.orders TO view_owner;
CREATE SCHEMA IF NOT EXISTS debug AUTHORIZATION view_owner;
ALTER SCHEMA debug OWNER TO view_owner;
REVOKE ALL ON SCHEMA debug FROM PUBLIC;

SET ROLE view_owner;
CREATE OR REPLACE VIEW debug.customers WITH (security_barrier) AS
  SELECT id,
         left(email, 2) || '***'     AS email,
         left(full_name, 1) || '***' AS full_name,
         created_at
  FROM public.customers;
CREATE OR REPLACE VIEW debug.orders AS
  SELECT id, customer_id, total, created_at FROM public.orders;
RESET ROLE;

-- debug_ro: CONNECT on app1, USAGE on debug, SELECT on the views. No grant on base tables and
-- no default privileges on schema public, so new tables stay invisible (fails closed).
GRANT CONNECT ON DATABASE app1 TO debug_ro;
GRANT USAGE ON SCHEMA debug TO debug_ro;
GRANT SELECT ON ALL TABLES IN SCHEMA debug TO debug_ro;
ALTER DEFAULT PRIVILEGES FOR ROLE view_owner IN SCHEMA debug GRANT SELECT ON TABLES TO debug_ro;

-- bao_admin: creates and drops the temp roles (CREATEROLE; PostgreSQL 16+ limits it to roles
-- it created or holds ADMIN OPTION on), hands out debug_ro, terminates temp sessions.
-- INHERIT FALSE, SET FALSE: bao_admin can grant debug_ro but cannot use it to read the views.
-- It is still a member for pg_hba purposes (+debug_ro), so its pg_hba line comes first.
GRANT debug_ro TO bao_admin WITH ADMIN TRUE, INHERIT FALSE, SET FALSE;
GRANT pg_signal_backend TO bao_admin;
GRANT CONNECT ON DATABASE app1 TO bao_admin;
SQL

psql_app1 -At -c "SELECT 'access-setup (pg): ok; debug views: ' || string_agg(table_name, ',' ORDER BY table_name) FROM information_schema.views WHERE table_schema = 'debug'"
