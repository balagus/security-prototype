#!/bin/bash
# First-init only (docker-entrypoint-initdb.d). Creates the app1 migrator/runtime split.
# Runs inside the image's temporary init server; connects over the local socket as
# postgres (peer auth in our pg_hba.conf). Passwords come from Docker secrets and are fed
# to psql on stdin (\set), so they never appear on a command line.
# Generated passwords are alphanumeric; :'var' quotes them as SQL literals anyway.
# The entrypoint sources this file when it is not executable, so no "set -u" and no "exit".
set -eo pipefail

mig_pw="$(cat /run/secrets/pg_app1_migrator_password)"
rt_pw="$(cat /run/secrets/pg_app1_runtime_password)"

{
printf '\\set mig_pw %s\n' "$mig_pw"
printf '\\set rt_pw %s\n' "$rt_pw"
cat <<'SQL'
CREATE ROLE app1_migrator LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD :'mig_pw';
CREATE ROLE app1_runtime  LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD :'rt_pw';

-- PG 15+: the database owner also owns schema public (via pg_database_owner).
ALTER DATABASE app1 OWNER TO app1_migrator;

REVOKE CONNECT, TEMPORARY ON DATABASE app1 FROM PUBLIC;
REVOKE CONNECT ON DATABASE postgres FROM PUBLIC;
GRANT CONNECT ON DATABASE app1 TO app1_migrator, app1_runtime;
SQL
} | psql -v ON_ERROR_STOP=1 --no-psqlrc --username postgres --dbname postgres

# Schema and default privileges are per database: run them inside app1.
psql -v ON_ERROR_STOP=1 --no-psqlrc --username postgres --dbname app1 <<'SQL'
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO app1_runtime;

ALTER DEFAULT PRIVILEGES FOR ROLE app1_migrator IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app1_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE app1_migrator IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO app1_runtime;
SQL

unset mig_pw rt_pw
echo "10-app1-roles: app1_migrator and app1_runtime created"
