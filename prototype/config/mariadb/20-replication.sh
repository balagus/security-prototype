#!/bin/bash
# Phase 3, first-init only (docker-entrypoint-initdb.d of maria-primary in compose.phase3.yaml).
# Creates the replication account of maria-replica:
#   - host = the replica's fixed address on maria-repl only, REQUIRE SSL;
#   - REPLICATION SLAVE: the binlog stream (GTID replication);
#   - the read privileges mariadb-dump needs to SEED the replica with a consistent copy of
#     every database including mysql (20-replica-seed.sh on the replica). See the note below.
# Password from the Docker secret, on stdin, never on a command line.
# The entrypoint may source this file, so no "set -u" and no "exit".
#
# Note: the dump privileges make this account able to read every table, including password
# hashes in mysql.global_priv. REPLICATION SLAVE alone already streams every change (and every
# CREATE USER with its hash) since the binlog starts, so the extra exposure is the history
# before the binlog. In production the seed is taken by a DBA with a separate account, or with
# mariadb-backup on the primary host, and this account keeps REPLICATION SLAVE only.
set -eo pipefail

if [ -z "${REPLICA_HOST:-}" ]; then
    echo "20-replication: REPLICA_HOST is not set (fixed address of maria-replica on maria-repl)" >&2
    false
fi

sql_quote() { printf "%s" "$1" | sed -e "s/\\\\/\\\\\\\\/g" -e "s/'/''/g"; }

root_pw="$(cat /run/secrets/maria_root_password)"
repl_pw="$(sql_quote "$(cat /run/secrets/maria_replicator_password)")"

mariadb --defaults-extra-file=<(printf '[client]\npassword=%s\n' "$root_pw") \
        --protocol=socket -uroot <<SQL
CREATE USER 'replicator'@'${REPLICA_HOST}' IDENTIFIED BY '${repl_pw}' REQUIRE SSL;
GRANT REPLICATION SLAVE ON *.* TO 'replicator'@'${REPLICA_HOST}';
-- Seed dump (mariadb-dump --all-databases --single-transaction --gtid --master-data=2).
GRANT SELECT, SHOW VIEW, TRIGGER, EVENT, LOCK TABLES, RELOAD, BINLOG MONITOR ON *.* TO 'replicator'@'${REPLICA_HOST}';
SQL

unset root_pw repl_pw
echo "20-replication: replicator created for host '${REPLICA_HOST}' (REQUIRE SSL)"
