#!/bin/bash
# First-init only (docker-entrypoint-initdb.d). Creates the app1 migrator/runtime split.
# Runs against the image's temporary init server over the local socket as root@localhost.
# Passwords come from Docker secrets and go to the client on stdin, never on a command line.
# The entrypoint may source this file, so no "set -u" and no "exit".
set -eo pipefail

if [ -z "${APP1_MARIA_HOSTMASK:-}" ]; then
    echo "10-app1-users: APP1_MARIA_HOSTMASK is not set (expected netmask form, e.g. 10.81.3.0/255.255.255.0)" >&2
    false
fi

# Escape for a single-quoted SQL literal (generated passwords are alphanumeric anyway).
sql_quote() { printf "%s" "$1" | sed -e "s/\\\\/\\\\\\\\/g" -e "s/'/''/g"; }

root_pw="$(cat /run/secrets/maria_root_password)"
mig_pw="$(sql_quote "$(cat /run/secrets/maria_app1_migrator_password)")"
rt_pw="$(sql_quote "$(cat /run/secrets/maria_app1_runtime_password)")"
host="$APP1_MARIA_HOSTMASK"

# The client reads the password from a defaults file on a pipe, not from argv or env.
mariadb --defaults-extra-file=<(printf '[client]\npassword=%s\n' "$root_pw") \
        --protocol=socket -uroot <<SQL
CREATE USER 'app1_runtime'@'$host' IDENTIFIED BY '$rt_pw' REQUIRE SSL;
GRANT SELECT, INSERT, UPDATE, DELETE ON app1.* TO 'app1_runtime'@'$host';

CREATE USER 'app1_migrator'@'$host' IDENTIFIED BY '$mig_pw' REQUIRE SSL;
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, DROP, INDEX, REFERENCES ON app1.* TO 'app1_migrator'@'$host';
SQL

unset root_pw mig_pw rt_pw
echo "10-app1-users: app1_migrator and app1_runtime created for host '$host'"
