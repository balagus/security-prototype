#!/bin/bash
# First-init only (docker-entrypoint-initdb.d of maria-primary). Creates the replication account
# of maria-replica:
#   - host = the replica's fixed address on maria-repl only, REQUIRE SSL;
#   - REPLICATION SLAVE: the binlog stream (GTID replication);
#   - the read privileges mariadb-dump needs to SEED the replica (20-replica-seed.sh). LAB-ONLY:
#     they let this account read every table, including the password hashes in
#     mysql.global_priv. In production the seed is taken by a DBA with a separate account, or
#     with mariadb-backup on the primary host, and this account keeps REPLICATION SLAVE only.
# The password is set with SET PASSWORD FOR on a locked account, so the binary log holds only
# its hash (see config/mariadb/10-app1-users.sh for the measured forms).
# Password from the Docker secret, on stdin, never on a command line.
# The entrypoint may source this file, so no "set -u" and no "exit".
#
# Remaining clear text: the replica stores this password in master.info (CHANGE MASTER). That is
# a file on the replica's data volume, not a log.
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
CREATE USER 'replicator'@'${REPLICA_HOST}' REQUIRE SSL ACCOUNT LOCK;
SET PASSWORD FOR 'replicator'@'${REPLICA_HOST}' = PASSWORD('${repl_pw}');
ALTER USER 'replicator'@'${REPLICA_HOST}' ACCOUNT UNLOCK;
GRANT REPLICATION SLAVE ON *.* TO 'replicator'@'${REPLICA_HOST}';
-- Seed dump (mariadb-dump --all-databases --single-transaction --gtid --master-data=2).
GRANT SELECT, SHOW VIEW, TRIGGER, EVENT, LOCK TABLES, RELOAD, BINLOG MONITOR ON *.* TO 'replicator'@'${REPLICA_HOST}';
SQL

unset root_pw repl_pw
echo "20-replication: replicator created for host '${REPLICA_HOST}' (REQUIRE SSL; password via SET PASSWORD FOR)"
