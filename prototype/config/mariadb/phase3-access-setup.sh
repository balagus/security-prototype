#!/bin/bash
# Phase 3: replica session sweeper account (design 5.1 / 5.4, MariaDB). Run on the PRIMARY by
# scripts/phase3-setup.ps1 after phase2-access-setup.sh, over the local socket as root:
#   docker exec <maria-primary> bash /opt/phase3/access-setup.sh
# The account replicates to maria-replica, where maria-sweeper uses it. Its host is the
# sweeper's fixed address on the access network, which the primary is not on.
# Idempotent: the password is re-set from the Docker secret on every run.
#
# Least privilege, measured (tests\phase3-checks.ps1):
#   PROCESS             needed: without it information_schema.PROCESSLIST shows only the
#                       account's own connections.
#   CONNECTION ADMIN    needed: KILL CONNECTION of another account's connection.
#   SELECT (User) ON mysql.user
#                       needed to see which accounts still exist. mysql.user is a view over
#                       mysql.global_priv; a column grant on the view is enough, so the sweeper
#                       cannot read authentication_string (password hashes) as it could with
#                       a table-wide SELECT on mysql.user.
set -euo pipefail

: "${SWEEPER_HOST:?SWEEPER_HOST is not set (fixed address of maria-sweeper on the access network)}"

sql_quote() { printf "%s" "$1" | sed -e "s/\\\\/\\\\\\\\/g" -e "s/'/''/g"; }

root_pw="$(cat /run/secrets/maria_root_password)"
sw_pw="$(sql_quote "$(cat /run/secrets/maria_session_sweeper_password)")"

mdb() { mariadb --defaults-extra-file=<(printf '[client]\npassword=%s\n' "$root_pw") --protocol=socket -uroot "$@"; }

mdb <<SQL
CREATE USER IF NOT EXISTS 'session_sweeper'@'${SWEEPER_HOST}' IDENTIFIED BY '${sw_pw}' REQUIRE SSL;
ALTER USER 'session_sweeper'@'${SWEEPER_HOST}' IDENTIFIED BY '${sw_pw}' REQUIRE SSL WITH MAX_USER_CONNECTIONS 2;
GRANT PROCESS, CONNECTION ADMIN ON *.* TO 'session_sweeper'@'${SWEEPER_HOST}';
GRANT SELECT (User) ON mysql.user TO 'session_sweeper'@'${SWEEPER_HOST}';
SQL

echo "phase3-access-setup (maria): ok; $(mdb -N -B -e "SHOW GRANTS FOR 'session_sweeper'@'${SWEEPER_HOST}'" | sed -e "s/ IDENTIFIED BY PASSWORD '[^']*'//" | tr '\n' ';')"
unset root_pw sw_pw
