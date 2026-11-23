#!/bin/bash
# Phase 3, first-init only (docker-entrypoint-initdb.d of pg-primary in compose.phase3.yaml).
# Creates the streaming-replication role and the physical replication slot of pg-replica.
# replicator has REPLICATION and nothing else: no database CONNECT, no table privileges.
# pg_hba.conf allows it only for "replication" connections from the replica's fixed address.
# The password comes from the Docker secret on stdin (\set), never on a command line.
# The entrypoint sources this file when it is not executable, so no "set -u" and no "exit".
set -eo pipefail

repl_pw="$(cat /run/secrets/pg_replicator_password)"

{
printf '\\set repl_pw %s\n' "$repl_pw"
cat <<'SQL'
CREATE ROLE replicator LOGIN REPLICATION NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS
  CONNECTION LIMIT 3 PASSWORD :'repl_pw';   -- pg_basebackup -X stream uses 2, streaming 1
-- The slot keeps the WAL the replica still needs while it is stopped (capped on the primary by
-- max_slot_wal_keep_size). Created here so the replica's pg_basebackup can simply use it.
SELECT pg_create_physical_replication_slot('pg_replica');
SQL
} | psql -v ON_ERROR_STOP=1 --no-psqlrc -q --username postgres --dbname postgres

unset repl_pw
echo "20-replication: role replicator and slot pg_replica created"
