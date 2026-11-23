#!/bin/bash
# PHASE 4 VARIANT of config/mariadb/phase2-access-setup.sh (compose.phase4.yaml only; phases 2
# and 3 keep the original). Same masked views and the same bao_admin account and grants on the
# PRIMARY; the difference is how bao_admin's initial password is set:
#   - The original runs "CREATE USER IF NOT EXISTS ... IDENTIFIED BY '<initial>'" on EVERY run.
#     Measured: MariaDB binlogs that statement with the clear-text password even when the
#     account already exists and nothing changes.
#   - Here bao_admin is created LOCKED without a password only if it does not exist, then gets
#     the initial password with SET PASSWORD FOR (binlogged as the hash) and is unlocked. An
#     existing bao_admin is never touched (OpenBao rotated its password; it is the only holder).
#
# In phase 4 bao_admin on the primary no longer creates the MariaDB temp users (they live on the
# replica, created by bao_replica_admin, see config/mariadb/phase4/replica-bao-account.sh). It
# stays for the OpenBao connection app1-maria (root rotation tests, the LAB-ONLY probe roles of
# tests\phase2-checks.ps1 and a future primary-side role such as the phase 5 break-glass role).
#
# Run by scripts/phase2-setup.ps1 after the migrations, over the local socket as root:
#   docker exec <maria-primary> bash /opt/phase2/access-setup.sh
# Idempotent. Passwords go to the client on stdin, never on a command line.
set -euo pipefail

: "${BAO_ADMIN_HOST:?BAO_ADMIN_HOST is not set (fixed address of OpenBao on the bao-admin network)}"

sql_quote() { printf "%s" "$1" | sed -e "s/\\\\/\\\\\\\\/g" -e "s/'/''/g"; }

root_pw="$(cat /run/secrets/maria_root_password)"
bao_pw="$(sql_quote "$(cat /run/secrets/maria_bao_admin_initial_password)")"

mdb() { mariadb --defaults-extra-file=<(printf '[client]\npassword=%s\n' "$root_pw") --protocol=socket -uroot "$@"; }

ready="$(mdb -N -B -e "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = 'app1' AND TABLE_NAME IN ('customers', 'orders')")"
if [ "$ready" != "2" ]; then
    echo "phase2-access-setup (maria, phase 4): tables app1.customers/app1.orders do not exist yet; run the migrations first" >&2
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
SQL

exists="$(mdb -N -B -e "SELECT COUNT(*) FROM mysql.global_priv WHERE User = 'bao_admin' AND Host = '${BAO_ADMIN_HOST}'")"
if [ "$exists" = "0" ]; then
    mdb <<SQL
-- bao_admin: only from OpenBao's fixed address, TLS required. Created locked and without a
-- password, then the initial password as a hash (SET PASSWORD FOR), then unlocked.
CREATE USER 'bao_admin'@'${BAO_ADMIN_HOST}' REQUIRE SSL ACCOUNT LOCK;
SET PASSWORD FOR 'bao_admin'@'${BAO_ADMIN_HOST}' = PASSWORD('${bao_pw}');
ALTER USER 'bao_admin'@'${BAO_ADMIN_HOST}' ACCOUNT UNLOCK;
SQL
    echo "phase2-access-setup (maria, phase 4): bao_admin created with the initial password (SET PASSWORD FOR: hash only in the binlog)"
else
    echo "phase2-access-setup (maria, phase 4): bao_admin exists; password left alone (OpenBao rotated it)"
fi

mdb <<SQL
-- Global CREATE USER lets it alter or drop ANY account: OpenBao compromise = account compromise.
ALTER USER 'bao_admin'@'${BAO_ADMIN_HOST}' REQUIRE SSL;
GRANT CREATE USER, CONNECTION ADMIN ON *.* TO 'bao_admin'@'${BAO_ADMIN_HOST}';
GRANT SELECT ON app1_masked.* TO 'bao_admin'@'${BAO_ADMIN_HOST}' WITH GRANT OPTION;
SQL

echo "phase2-access-setup (maria, phase 4): ok; app1_masked views: $(mdb -N -B -e "SELECT GROUP_CONCAT(TABLE_NAME ORDER BY TABLE_NAME) FROM information_schema.VIEWS WHERE TABLE_SCHEMA = 'app1_masked'")"
unset root_pw bao_pw
