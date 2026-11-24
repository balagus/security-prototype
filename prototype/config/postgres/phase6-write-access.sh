#!/bin/bash
# Phase 6: the developer WRITE path on PostgreSQL (design 4.C "Write and break-glass path").
# NOT a first-init script: it needs the tables that dotnet-migrate creates and the role
# bao_admin from phase2-access-setup.sh. scripts/phase6-setup.ps1 runs it as OS user postgres
# over the local socket (peer auth):
#   docker exec -u postgres <pg-primary> bash /opt/phase6/write-access.sh
# Idempotent; run it again after any migration that recreates public.customers or public.orders
# (a dropped table loses its trigger; the setup checks for it).
#
# What it creates:
#   debug_rw   NOLOGIN group role of the OpenBao role app1-pg-rw (temp users on the PRIMARY).
#              SELECT, INSERT, UPDATE, DELETE on an explicit allow-list of base tables. No
#              TRUNCATE, no DDL, no other schema. Not a member of debug_ro, so the replica's
#              pg_hba refuses its members (they match no allow line there).
#   dev_audit  schema owned by the NOLOGIN role audit_owner. Nobody else has USAGE on it.
#     .row_changes          one row per row changed by a developer temp user: who, when,
#                           transaction, table, operation, old and new row (jsonb).
#     .capture()            AFTER ROW trigger function (SECURITY DEFINER, owner audit_owner). It
#                           returns at once unless session_user is a temp user ("v-..."), so the
#                           application's own writes cost one comparison. For a temp user it
#                           inserts into row_changes (same transaction: a rollback removes the
#                           row, exactly like the change itself) AND writes one LOG line
#                           "DEV_CHANGE: {json}" to the server log, which fluent-bit ships to
#                           the audit store (written even if the transaction rolls back; the
#                           txid joins it to the commit or abort).
#     .enable_session_audit(name)  SECURITY DEFINER, owner postgres, EXECUTE for bao_admin only.
#                           Called by the OpenBao creation statements. It sets full pgAudit
#                           logging ON THE TEMP ROLE ITSELF (a setting on debug_rw would not reach
#                           its members, design 4.E). It refuses anything that is not an existing
#                           "v-" login role, member of debug_rw, without superuser/createrole/
#                           replication/bypassrls. If it fails, the creation fails and OpenBao
#                           hands out no credentials (fails closed). It is the only way bao_admin
#                           can touch pgaudit.* settings: bao_admin gets no SET privilege on them.
#   Triggers   zz_dev_audit on every table of the allow-list.
#   bao_admin  ADMIN OPTION on debug_rw (INHERIT FALSE, SET FALSE: it cannot use it itself).
set -euo pipefail

psql_app1() { psql -v ON_ERROR_STOP=1 -X -q --no-psqlrc -d app1 "$@"; }

ready="$(psql_app1 -At -c "SELECT (to_regclass('public.customers') IS NOT NULL AND to_regclass('public.orders') IS NOT NULL AND EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'bao_admin'))::text")"
if [ "$ready" != "true" ]; then
    echo "phase6-write-access (pg): public.customers/public.orders or bao_admin missing; run the migrations and phase2-setup first" >&2
    exit 1
fi

psql_app1 <<'SQL'
SET client_min_messages = warning;
SELECT NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'debug_rw')    AS need_debug_rw,
       NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'audit_owner') AS need_audit_owner \gset
\if :need_debug_rw
CREATE ROLE debug_rw NOLOGIN;
\endif
\if :need_audit_owner
CREATE ROLE audit_owner NOLOGIN;
\endif
ALTER ROLE debug_rw    NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE audit_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;

-- ---- debug_rw: explicit allow-list of base tables -------------------------------------------
-- Writing through UPDATE/DELETE ... WHERE needs SELECT on the columns used, so the write path
-- sees the real (unmasked) data of these tables. That is why it is a separate, rarer request.
GRANT CONNECT ON DATABASE app1 TO debug_rw;
GRANT USAGE ON SCHEMA public TO debug_rw;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.customers, public.orders TO debug_rw;
-- Belt and braces: nothing the allow-list does not name.
REVOKE TRUNCATE, REFERENCES, TRIGGER ON public.customers, public.orders FROM debug_rw;

-- OpenBao hands debug_rw to the temp users. bao_admin cannot read or write with it itself.
GRANT debug_rw TO bao_admin WITH ADMIN TRUE, INHERIT FALSE, SET FALSE;

-- ---- dev_audit ---------------------------------------------------------------------------------
CREATE SCHEMA IF NOT EXISTS dev_audit AUTHORIZATION audit_owner;
ALTER SCHEMA dev_audit OWNER TO audit_owner;
REVOKE ALL ON SCHEMA dev_audit FROM PUBLIC;

CREATE TABLE IF NOT EXISTS dev_audit.row_changes (
    id               bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    changed_at       timestamptz NOT NULL DEFAULT clock_timestamp(),
    db_user          text        NOT NULL,
    txid             bigint      NOT NULL,
    backend_pid      integer     NOT NULL,
    client_addr      inet,
    application_name text,
    table_name       text        NOT NULL,
    operation        text        NOT NULL,
    old_row          jsonb,
    new_row          jsonb
);
ALTER TABLE dev_audit.row_changes OWNER TO audit_owner;
REVOKE ALL ON dev_audit.row_changes FROM PUBLIC;

CREATE OR REPLACE FUNCTION dev_audit.capture() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $fn$
DECLARE
    o jsonb;
    n jsonb;
    rec jsonb;
BEGIN
    -- session_user: the login role. SET ROLE cannot hide it (and temp users cannot SET ROLE to
    -- anything but debug_rw anyway).
    IF left(session_user::text, 2) <> 'v-' THEN
        RETURN NULL;
    END IF;
    IF TG_OP IN ('UPDATE', 'DELETE') THEN o := to_jsonb(OLD); END IF;
    IF TG_OP IN ('INSERT', 'UPDATE') THEN n := to_jsonb(NEW); END IF;
    INSERT INTO dev_audit.row_changes (db_user, txid, backend_pid, client_addr, application_name, table_name, operation, old_row, new_row)
    VALUES (session_user, txid_current(), pg_backend_pid(), inet_client_addr(), current_setting('application_name', true),
            TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME, TG_OP, o, n);
    rec := jsonb_build_object('db_user', session_user::text, 'txid', txid_current(), 'pid', pg_backend_pid(),
                              'table', TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME, 'op', TG_OP, 'old', o, 'new', n);
    -- LOG goes to the server log (log_min_messages default WARNING lets LOG through) and not to
    -- the client (client_min_messages default NOTICE). Neither is settable by a temp user.
    RAISE LOG 'DEV_CHANGE: %', rec::text;
    RETURN NULL;
END
$fn$;
ALTER FUNCTION dev_audit.capture() OWNER TO audit_owner;
REVOKE ALL ON FUNCTION dev_audit.capture() FROM PUBLIC;

-- Triggers on the allow-list. "zz_" so they run after any application trigger and see the
-- final row.
DROP TRIGGER IF EXISTS zz_dev_audit ON public.customers;
CREATE TRIGGER zz_dev_audit AFTER INSERT OR UPDATE OR DELETE ON public.customers
    FOR EACH ROW EXECUTE FUNCTION dev_audit.capture();
DROP TRIGGER IF EXISTS zz_dev_audit ON public.orders;
CREATE TRIGGER zz_dev_audit AFTER INSERT OR UPDATE OR DELETE ON public.orders
    FOR EACH ROW EXECUTE FUNCTION dev_audit.capture();

-- Per-temp-role pgAudit settings. Owner postgres (only a superuser may set pgaudit.* on a role).
CREATE OR REPLACE FUNCTION dev_audit.enable_session_audit(role_name text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $fn$
DECLARE
    r pg_roles%ROWTYPE;
BEGIN
    IF role_name IS NULL OR role_name !~ '^v-[A-Za-z0-9._@-]{1,61}$' THEN
        RAISE EXCEPTION 'enable_session_audit: refused role name %', coalesce(role_name, '<null>') USING ERRCODE = '42501';
    END IF;
    SELECT * INTO r FROM pg_roles WHERE rolname = role_name;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'enable_session_audit: role % does not exist', role_name USING ERRCODE = '42704';
    END IF;
    IF NOT r.rolcanlogin OR r.rolsuper OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication OR r.rolbypassrls THEN
        RAISE EXCEPTION 'enable_session_audit: role % has unexpected attributes', role_name USING ERRCODE = '42501';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_auth_members m JOIN pg_roles g ON g.oid = m.roleid
                   WHERE m.member = r.oid AND g.rolname = 'debug_rw') THEN
        RAISE EXCEPTION 'enable_session_audit: role % is not a member of debug_rw', role_name USING ERRCODE = '42501';
    END IF;
    EXECUTE format('ALTER ROLE %I SET pgaudit.log = %L', role_name, 'read, write, ddl, role, function, misc');
    EXECUTE format('ALTER ROLE %I SET pgaudit.log_catalog = off', role_name);
    EXECUTE format('ALTER ROLE %I SET pgaudit.log_relation = on', role_name);
    EXECUTE format('ALTER ROLE %I SET pgaudit.log_parameter = on', role_name);
    EXECUTE format('ALTER ROLE %I SET pgaudit.log_rows = on', role_name);
END
$fn$;
ALTER FUNCTION dev_audit.enable_session_audit(text) OWNER TO postgres;
REVOKE ALL ON FUNCTION dev_audit.enable_session_audit(text) FROM PUBLIC;
GRANT USAGE ON SCHEMA dev_audit TO bao_admin;
GRANT EXECUTE ON FUNCTION dev_audit.enable_session_audit(text) TO bao_admin;
SQL

psql_app1 -At -c "SELECT 'phase6-write-access (pg): ok; debug_rw tables: ' || string_agg(DISTINCT table_schema || '.' || table_name, ',') || '; triggers: ' || (SELECT string_agg(tgrelid::regclass::text, ',' ORDER BY tgrelid::regclass::text) FROM pg_trigger WHERE tgname = 'zz_dev_audit') FROM information_schema.role_table_grants WHERE grantee = 'debug_rw'"
