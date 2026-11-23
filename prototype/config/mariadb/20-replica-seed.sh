#!/bin/bash
# Phase 3, first-init only (docker-entrypoint-initdb.d of maria-replica in compose.phase3.yaml).
# Seeds the replica the way one would from an existing production primary:
#   1. a consistent dump of the primary, ALL databases including the mysql system database
#      (so every existing account, bao_admin and the app accounts included, is present), taken
#      in one transaction with the matching GTID position (--single-transaction --gtid
#      --master-data=2), over TLS with server certificate verification;
#   2. loaded into the replica's temporary init server;
#   3. gtid_slave_pos set to the dump's position, CHANGE MASTER ... MASTER_USE_GTID=slave_pos
#      with MASTER_SSL=1 and MASTER_SSL_VERIFY_SERVER_CERT=1. The image's final server start
#      then starts replication (no --skip-slave-start).
# Runs inside the image entrypoint after the root account is set up; the temporary server has
# no networking, but this client connects OUT to the primary over TCP.
# Passwords go to the clients in defaults files on pipes, never on a command line.
# The entrypoint may source this file, so no "set -u" and no "exit".
set -eo pipefail

datadir=/var/lib/mysql
# Removed again at the very end. If it survives (the seed was interrupted), replica-entrypoint.sh
# wipes the data directory on the next start, so the seed runs again.
touch "$datadir/.replica-seed-incomplete"

sql_quote() { printf "%s" "$1" | sed -e "s/\\\\/\\\\\\\\/g" -e "s/'/''/g"; }

primary="${MARIADB_PRIMARY_HOST:-maria-primary}"
root_pw="$(cat /run/secrets/maria_root_password)"
repl_pw_raw="$(cat /run/secrets/maria_replicator_password)"
repl_pw="$(sql_quote "$repl_pw_raw")"
remote_cnf() { printf '[client]\nuser=replicator\npassword=%s\nhost=%s\nport=3306\nssl-ca=/pki-ca/ca.crt\nssl-verify-server-cert\n' "$repl_pw_raw" "$primary"; }
local_sql() { mariadb --defaults-extra-file=<(printf '[client]\npassword=%s\n' "$root_pw") --protocol=socket -uroot "$@"; }

echo "20-replica-seed: waiting for $primary"
tries=0
until mariadb --defaults-extra-file=<(remote_cnf) --connect-timeout=5 -N -B -e 'SELECT 1' > /dev/null; do
    tries=$((tries + 1))
    if [ "$tries" -ge 60 ]; then echo "20-replica-seed: $primary not reachable as replicator" >&2; false; fi
    sleep 3
done

dump=/tmp/replica-seed.sql
(umask 077; mariadb-dump --defaults-extra-file=<(remote_cnf) \
    --all-databases --single-transaction --gtid --master-data=2 \
    --routines --events --triggers --hex-blob --flush-privileges > "$dump")
gtid="$(grep -m1 -oE "gtid_slave_pos='[^']*'" "$dump" | sed -e "s/gtid_slave_pos='//" -e "s/'\$//")"
if [ -z "$gtid" ]; then echo "20-replica-seed: no GTID position in the dump" >&2; rm -f "$dump"; false; fi
echo "20-replica-seed: dump of $primary taken at GTID $gtid ($(wc -c < "$dump") bytes)"

local_sql < "$dump"
rm -f "$dump"

# The dump replaced the replica's own healthcheck accounts with the primary's (another random
# password). Give them back the password from this replica's .my-healthcheck.cnf, plus
# REPLICA MONITOR for the replication healthcheck. Local-only accounts, never replicated.
hc_pw="$(sql_quote "$(sed -n 's/^password=//p' "$datadir/.my-healthcheck.cnf")")"

local_sql <<SQL
SET SESSION sql_log_bin = 0;
FLUSH PRIVILEGES;
SET PASSWORD FOR healthcheck@'127.0.0.1' = PASSWORD('${hc_pw}');
SET PASSWORD FOR healthcheck@'::1' = PASSWORD('${hc_pw}');
SET PASSWORD FOR healthcheck@'localhost' = PASSWORD('${hc_pw}');
GRANT REPLICA MONITOR ON *.* TO healthcheck@'127.0.0.1', healthcheck@'::1', healthcheck@'localhost';
SET GLOBAL gtid_slave_pos = '${gtid}';
CHANGE MASTER TO
  MASTER_HOST = '${primary}', MASTER_PORT = 3306,
  MASTER_USER = 'replicator', MASTER_PASSWORD = '${repl_pw}',
  MASTER_SSL = 1, MASTER_SSL_CA = '/pki-ca/ca.crt', MASTER_SSL_VERIFY_SERVER_CERT = 1,
  MASTER_USE_GTID = slave_pos, MASTER_CONNECT_RETRY = 10;
SQL

unset root_pw repl_pw repl_pw_raw hc_pw
rm -f "$datadir/.replica-seed-incomplete"
echo "20-replica-seed: replica seeded at GTID $gtid; replication starts with the server"
