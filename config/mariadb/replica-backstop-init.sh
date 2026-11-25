#!/bin/bash
# Entrypoint of maria-replica (compose.yaml). Runs as root at EVERY container start, then hands
# over to /opt/replica/replica-entrypoint.sh (half-seed wipe, then the image's
# docker-entrypoint.sh).
#
# Revocation backstops (docs/DECISIONS.md D8):
#   1. renders the server's init_file from /opt/replica/replica-init.sql.tmpl into
#      /etc/mysql/replica-init/init.sql (root-owned, no secrets in it): the startup purge of all
#      local v- users and the expiry backstop event. The server runs it with --init-file at every
#      start, BEFORE it opens the network listener (see the template);
#   2. creates the backstop log directory on the replica's audit volume
#      (/var/log/mariadb-audit/backstop, owner mysql, group 4000 inherited from the setgid parent,
#      mode 2750). It is the server's --secure-file-priv directory: the purge and the event write
#      one line per action there with SELECT ... INTO OUTFILE, and Fluent Bit ships the files.
#      MariaDB creates INTO OUTFILE files with mode 0644 whatever the umask (measured); the
#      2750 directories (this one and its parent) keep everybody but mysql and group 4000 out.
# Configuration (environment, digits only; validated here because the values end up in SQL):
#   BACKSTOP_INTERVAL_SECONDS  how often the event runs
#   BACKSTOP_MAX_TTL_SECONDS   the OpenBao role's max_ttl (app1-maria-ro: 4h = 14400)
#   BACKSTOP_MARGIN_SECONDS    extra time before a user counts as left behind
set -euo pipefail

for v in BACKSTOP_INTERVAL_SECONDS BACKSTOP_MAX_TTL_SECONDS BACKSTOP_MARGIN_SECONDS; do
    val="${!v:-}"
    if ! [[ "$val" =~ ^[0-9]{1,9}$ ]] || [ "$val" -lt 1 ]; then
        echo "maria-replica: $v must be a positive integer (got '$val')" >&2
        exit 2
    fi
done

backstop_dir=/var/log/mariadb-audit/backstop
mkdir -p "$backstop_dir"
chown mysql "$backstop_dir"
chmod 2750 "$backstop_dir"

mkdir -p /etc/mysql/replica-init
sed -e "s#@@BACKSTOP_INTERVAL_SECONDS@@#${BACKSTOP_INTERVAL_SECONDS}#g" \
    -e "s#@@BACKSTOP_MAX_TTL_SECONDS@@#${BACKSTOP_MAX_TTL_SECONDS}#g" \
    -e "s#@@BACKSTOP_MARGIN_SECONDS@@#${BACKSTOP_MARGIN_SECONDS}#g" \
    -e "s#@@BACKSTOP_DIR@@#${backstop_dir}#g" \
    /opt/replica/replica-init.sql.tmpl > /etc/mysql/replica-init/init.sql
chmod 0644 /etc/mysql/replica-init/init.sql
if grep -q '@@BACKSTOP_' /etc/mysql/replica-init/init.sql; then
    echo "maria-replica: unrendered placeholder in init.sql" >&2
    exit 2
fi
echo "maria-replica: init_file rendered (startup purge; backstop every ${BACKSTOP_INTERVAL_SECONDS}s, max_ttl ${BACKSTOP_MAX_TTL_SECONDS}s + margin ${BACKSTOP_MARGIN_SECONDS}s)"

exec bash /opt/replica/replica-entrypoint.sh "$@"
