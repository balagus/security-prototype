#!/bin/bash
# PHASE 4 VARIANT of config/mariadb/20-replica-seed.sh (compose.phase4.yaml only; phase 3 keeps
# the original). Two differences, both in step 2 (the load):
#   a. The load runs with sql_log_bin = 0. The phase 4 replica writes its own binary log
#      (log_bin, log_slave_updates); loading the dump with binlogging on would give every
#      loaded statement a local GTID 0-2-n, and with gtid_strict_mode the replica could then not
#      set gtid_slave_pos to the dump's (lower) position. It would also put the dump, with every
#      password hash, into the replica's binlog.
#   b. server_audit does not record the load. The dump INSERTs every account's password hash
#      into mysql.global_priv; in phase 3/4 that statement landed in the replica's audit log and
#      in the shipped store. server_audit has no per-session switch and server_audit_excl_users
#      would also hide the restoring statement, so logging is switched OFF globally around the
#      load and ON again. Both SET GLOBAL statements are themselves audited (they stay as a
#      record that the load was not audited). This runs inside the image's temporary init
#      server, which has no network (--skip-networking): nothing else can run meanwhile. The
#      final server starts with --server-audit-logging=ON from the command line in any case.
#
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

# Phase 4: (b) no audit record of the load, (a) no binlogging of it.
local_sql -e "SET GLOBAL server_audit_logging = OFF"
local_sql --init-command='SET SESSION sql_log_bin = 0' < "$dump"
local_sql -e "SET GLOBAL server_audit_logging = ON"
rm -f "$dump"
echo "20-replica-seed: dump loaded with sql_log_bin = 0 and server_audit_logging OFF (back ON: $(local_sql -N -B -e 'SELECT @@server_audit_logging'))"

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
