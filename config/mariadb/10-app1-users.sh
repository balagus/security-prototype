#!/bin/bash
# Application accounts of maria-primary (docs/DECISIONS.md D2): app1_migrator (DDL, used only by
# laravel-migrate) and app1_runtime (DML only), both limited to the app1-maria subnet, REQUIRE SSL.
#
# Measured on MariaDB 11.8 (tests\audit-checks.ps1): the binary log keeps
#   CREATE USER / ALTER USER ... IDENTIFIED BY '<pw>'                   clear text
#   ... IDENTIFIED VIA mysql_native_password USING PASSWORD('<pw>')     clear text
#   GRANT ... IDENTIFIED BY '<pw>'                                      clear text
#   CREATE USER IF NOT EXISTS ... IDENTIFIED BY '<pw>' (account exists) clear text, although
#                                                                       nothing changes
#   SET PASSWORD FOR ... = PASSWORD('<pw>')                             only the native hash
#   CREATE USER ... IDENTIFIED BY PASSWORD '<hash>'                     only the native hash
# server_audit masks all of them. So: create the account LOCKED and without a password, set
# the password with SET PASSWORD FOR, then unlock it. The binlog (and the replica's relay log
# and binlog) get "SET PASSWORD FOR ...='*<hash>'".
#
# First-init only (docker-entrypoint-initdb.d). Runs against the image's temporary init server
# over the local socket as root@localhost. Passwords come from Docker secrets and go to the
# client on stdin, never on a command line. The entrypoint may source this file, so no
# "set -u" and no "exit".
set -eo pipefail

if [ -z "${APP1_MARIA_HOSTMASK:-}" ]; then
    echo "10-app1-users: APP1_MARIA_HOSTMASK is not set (expected netmask form, e.g. 10.81.3.0/255.255.255.0)" >&2
    false
fi

sql_quote() { printf "%s" "$1" | sed -e "s/\\\\/\\\\\\\\/g" -e "s/'/''/g"; }

root_pw="$(cat /run/secrets/maria_root_password)"
mig_pw="$(sql_quote "$(cat /run/secrets/maria_app1_migrator_password)")"
rt_pw="$(sql_quote "$(cat /run/secrets/maria_app1_runtime_password)")"
host="$APP1_MARIA_HOSTMASK"

mariadb --defaults-extra-file=<(printf '[client]\npassword=%s\n' "$root_pw") \
        --protocol=socket -uroot <<SQL
CREATE USER 'app1_runtime'@'$host' REQUIRE SSL ACCOUNT LOCK;
SET PASSWORD FOR 'app1_runtime'@'$host' = PASSWORD('$rt_pw');
ALTER USER 'app1_runtime'@'$host' ACCOUNT UNLOCK;
GRANT SELECT, INSERT, UPDATE, DELETE ON app1.* TO 'app1_runtime'@'$host';

CREATE USER 'app1_migrator'@'$host' REQUIRE SSL ACCOUNT LOCK;
SET PASSWORD FOR 'app1_migrator'@'$host' = PASSWORD('$mig_pw');
ALTER USER 'app1_migrator'@'$host' ACCOUNT UNLOCK;
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, DROP, INDEX, REFERENCES ON app1.* TO 'app1_migrator'@'$host';
SQL

unset root_pw mig_pw rt_pw
echo "10-app1-users: app1_migrator and app1_runtime created for host '$host' (passwords via SET PASSWORD FOR: hash only in the binlog)"
