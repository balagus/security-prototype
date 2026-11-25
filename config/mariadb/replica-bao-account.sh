#!/bin/bash
# OpenBao's own account on maria-replica, bao_replica_admin (docs/DECISIONS.md D6, temp users
# on the replica). Run by scripts/setup-audit.ps1 over the replica's local socket as root:
#   docker exec <maria-replica> bash /opt/setup/replica-bao-account.sh ensure
#   docker exec -e BAO_REPLICA_PW <maria-replica> bash /opt/setup/replica-bao-account.sh set-password
#
# The account is LOCAL to the replica: every statement here runs with sql_log_bin = 0, so it is
# not in the replica's binary log, never reaches the primary (the replica does not replicate
# back) and does not exist there. It is lost when the replica is re-seeded (the seed loads the
# primary's mysql database); setup-audit.ps1 then creates it again and gives OpenBao a new
# initial password, which OpenBao rotates at once.
#
# Host: OpenBao's fixed address on the dedicated network bao-replica (BAO_REPLICA_ADMIN_HOST,
# 10.81.9.10). Only OpenBao (.10) and the replica (.12) are on that network.
#
# Privileges, each measured by removing it (tests\audit-checks.ps1 repeats the matrix):
#   CREATE USER        CREATE USER / DROP USER of the temp users ("Access denied; you need ...
#                      the CREATE USER privilege").
#   READ ONLY ADMIN    the replica runs with read_only=ON: without it CREATE USER, DROP USER and
#                      OpenBao's own SET PASSWORD (root rotation) fail with "running with the
#                      --read-only option".
#   BINLOG ADMIN       to set sql_log_bin = 0 ("you need ... the BINLOG ADMIN privilege"). SUPER
#                      alone is NOT enough in MariaDB 11.8 (measured).
#   CONNECTION ADMIN   KILL USER in the revocation statement. Without it KILL USER returns NO
#                      error and kills nothing: the open session survives the revocation.
#   SELECT ON app1_masked.* WITH GRANT OPTION
#                      to GRANT SELECT ON app1_masked.* to the temp user (without the grant
#                      option: "Access denied for user ... to database 'app1_masked'").
# Not granted: anything on app1.*, mysql.*, SUPER, PROCESS, REPLICA/REPLICATION privileges.
#
# set-password: the password comes in BAO_REPLICA_PW (an environment variable of "docker exec",
# never a command line) and is set with SET PASSWORD FOR ... = PASSWORD(...): server_audit masks
# it (PASSWORD(*****)), sql_log_bin = 0 keeps it out of the replica's binary log. The account is
# created locked and only unlocked once it has a password.
set -euo pipefail

: "${BAO_REPLICA_ADMIN_HOST:?BAO_REPLICA_ADMIN_HOST is not set (fixed address of OpenBao on bao-replica)}"
ACCOUNT="'bao_replica_admin'@'${BAO_REPLICA_ADMIN_HOST}'"

sql_quote() { printf "%s" "$1" | sed -e "s/\\\\/\\\\\\\\/g" -e "s/'/''/g"; }
root_pw="$(cat /run/secrets/maria_root_password)"
mdb() { mariadb --defaults-extra-file=<(printf '[client]\npassword=%s\n' "$root_pw") --protocol=socket -uroot "$@"; }
strip_hash() { sed -e "s/ IDENTIFIED BY PASSWORD '[^']*'//"; }


do_ensure() {
    local existed
    existed="$(mdb -N -B -e "SELECT COUNT(*) FROM mysql.global_priv WHERE User = 'bao_replica_admin' AND Host = '${BAO_REPLICA_ADMIN_HOST}'")"
    mdb <<SQL
SET SESSION sql_log_bin = 0;
CREATE USER IF NOT EXISTS ${ACCOUNT} REQUIRE SSL ACCOUNT LOCK;
ALTER USER ${ACCOUNT} REQUIRE SSL;
GRANT CREATE USER, READ ONLY ADMIN, BINLOG ADMIN, CONNECTION ADMIN ON *.* TO ${ACCOUNT};
GRANT SELECT ON app1_masked.* TO ${ACCOUNT} WITH GRANT OPTION;
SQL
    if [ "$existed" = "0" ]; then echo "replica-bao-account: created (locked, no password yet)"; else echo "replica-bao-account: exists"; fi
}

do_set_password() {
    local pw
    : "${BAO_REPLICA_PW:?BAO_REPLICA_PW is not set}"
    pw="$(sql_quote "$BAO_REPLICA_PW")"
    mdb <<SQL
SET SESSION sql_log_bin = 0;
SET PASSWORD FOR ${ACCOUNT} = PASSWORD('${pw}');
ALTER USER ${ACCOUNT} ACCOUNT UNLOCK;
SQL
    unset pw BAO_REPLICA_PW
    echo "replica-bao-account: initial password set, account unlocked"
}

if [ "${1:-}" = "ensure" ]; then
    do_ensure
elif [ "${1:-}" = "set-password" ]; then
    do_set_password
elif [ "${1:-}" = "show" ]; then
    mdb -N -B -e "SHOW GRANTS FOR ${ACCOUNT}" | strip_hash
else
    echo "usage: $0 ensure|set-password|show" >&2
    exit 2
fi
unset root_pw