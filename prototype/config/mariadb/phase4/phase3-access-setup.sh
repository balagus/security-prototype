#!/bin/bash
# PHASE 4 VARIANT of config/mariadb/phase3-access-setup.sh (compose.phase4.yaml only; phase 3
# keeps the original). Same session_sweeper account and grants (PROCESS, CONNECTION ADMIN,
# SELECT (User) ON mysql.user; reasons in the original). The password is set with
# SET PASSWORD FOR, binlogged as the hash, instead of CREATE/ALTER USER ... IDENTIFIED BY, which
# the original ran on every setup run and which put the clear-text password into the primary's
# binlog and the replica's relay log each time. A new account is created locked and unlocked
# only after it has its password, so it never exists without one on the replica.
#
# Run on the PRIMARY by scripts/phase3-setup.ps1 (via phase4-setup.ps1), local socket as root:
#   docker exec <maria-primary> bash /opt/phase3/access-setup.sh
# Idempotent: the password is re-set from the Docker secret on every run.
set -euo pipefail

: "${SWEEPER_HOST:?SWEEPER_HOST is not set (fixed address of maria-sweeper on the access network)}"

sql_quote() { printf "%s" "$1" | sed -e "s/\\\\/\\\\\\\\/g" -e "s/'/''/g"; }

root_pw="$(cat /run/secrets/maria_root_password)"
sw_pw="$(sql_quote "$(cat /run/secrets/maria_session_sweeper_password)")"

mdb() { mariadb --defaults-extra-file=<(printf '[client]\npassword=%s\n' "$root_pw") --protocol=socket -uroot "$@"; }

mdb <<SQL
CREATE USER IF NOT EXISTS 'session_sweeper'@'${SWEEPER_HOST}' REQUIRE SSL ACCOUNT LOCK;
SET PASSWORD FOR 'session_sweeper'@'${SWEEPER_HOST}' = PASSWORD('${sw_pw}');
ALTER USER 'session_sweeper'@'${SWEEPER_HOST}' REQUIRE SSL WITH MAX_USER_CONNECTIONS 2 ACCOUNT UNLOCK;
GRANT PROCESS, CONNECTION ADMIN ON *.* TO 'session_sweeper'@'${SWEEPER_HOST}';
GRANT SELECT (User) ON mysql.user TO 'session_sweeper'@'${SWEEPER_HOST}';
SQL

echo "phase3-access-setup (maria, phase 4): ok; $(mdb -N -B -e "SHOW GRANTS FOR 'session_sweeper'@'${SWEEPER_HOST}'" | sed -e "s/ IDENTIFIED BY PASSWORD '[^']*'//" | tr '\n' ';')"
unset root_pw sw_pw
