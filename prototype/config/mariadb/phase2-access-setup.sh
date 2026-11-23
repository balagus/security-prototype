#!/bin/bash
# Phase 2: database side of developer just-in-time access (design section 5.1, MariaDB).
# NOT a first-init script: the masked views need the tables that laravel-migrate creates, so
# scripts/phase2-setup.ps1 runs this after the migrations, over the local socket as root:
#   docker exec <maria-primary> bash /opt/phase2/access-setup.sh
# Idempotent. "CREATE USER IF NOT EXISTS" never resets the bao_admin password once the account
# exists, because OpenBao rotates it (rotate-root) and is then the only holder.
# Passwords go to the client in a defaults file on a pipe or on stdin, never on a command line.
set -euo pipefail

: "${BAO_ADMIN_HOST:?BAO_ADMIN_HOST is not set (fixed address of OpenBao on the bao-admin network)}"

sql_quote() { printf "%s" "$1" | sed -e "s/\\\\/\\\\\\\\/g" -e "s/'/''/g"; }

root_pw="$(cat /run/secrets/maria_root_password)"
bao_pw="$(sql_quote "$(cat /run/secrets/maria_bao_admin_initial_password)")"

mdb() { mariadb --defaults-extra-file=<(printf '[client]\npassword=%s\n' "$root_pw") --protocol=socket -uroot "$@"; }

ready="$(mdb -N -B -e "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = 'app1' AND TABLE_NAME IN ('customers', 'orders')")"
if [ "$ready" != "2" ]; then
    echo "phase2-access-setup (maria): tables app1.customers/app1.orders do not exist yet; run the migrations first" >&2
    exit 1
fi

mdb <<SQL
-- Masked surface: database app1_masked holds only reviewed views.
CREATE DATABASE IF NOT EXISTS app1_masked;

-- View definer: a locked account (cannot log in) with SELECT on an explicit table allow-list.
CREATE USER IF NOT EXISTS 'view_owner'@'localhost' ACCOUNT LOCK;
ALTER USER 'view_owner'@'localhost' ACCOUNT LOCK;
GRANT SELECT ON app1.customers TO 'view_owner'@'localhost';
GRANT SELECT ON app1.orders TO 'view_owner'@'localhost';

CREATE OR REPLACE DEFINER = 'view_owner'@'localhost' SQL SECURITY DEFINER VIEW app1_masked.customers AS
  SELECT id,
         CONCAT(LEFT(email, 2), '***')     AS email,
         CONCAT(LEFT(full_name, 1), '***') AS full_name,
         created_at
  FROM app1.customers;
CREATE OR REPLACE DEFINER = 'view_owner'@'localhost' SQL SECURITY DEFINER VIEW app1_masked.orders AS
  SELECT id, customer_id, total, created_at FROM app1.orders;

-- bao_admin: only from OpenBao's fixed address, TLS required.
-- Global CREATE USER lets it alter or drop ANY account: OpenBao compromise = account compromise.
CREATE USER IF NOT EXISTS 'bao_admin'@'${BAO_ADMIN_HOST}' IDENTIFIED BY '${bao_pw}' REQUIRE SSL;
ALTER USER 'bao_admin'@'${BAO_ADMIN_HOST}' REQUIRE SSL;
GRANT CREATE USER, CONNECTION ADMIN ON *.* TO 'bao_admin'@'${BAO_ADMIN_HOST}';
GRANT SELECT ON app1_masked.* TO 'bao_admin'@'${BAO_ADMIN_HOST}' WITH GRANT OPTION;
SQL

echo "phase2-access-setup (maria): ok; app1_masked views: $(mdb -N -B -e "SELECT GROUP_CONCAT(TABLE_NAME ORDER BY TABLE_NAME) FROM information_schema.VIEWS WHERE TABLE_SCHEMA = 'app1_masked'")"
unset root_pw bao_pw
