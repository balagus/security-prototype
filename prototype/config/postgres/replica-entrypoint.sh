#!/bin/bash
# Phase 3: entrypoint of pg-replica (compose.phase3.yaml). Runs as root, then hands over to the
# image's docker-entrypoint.sh, which drops to user postgres.
#   1. Builds the libpq passfile for the replicator from the Docker secret (every start; the
#      container file system is not persistent). primary_conninfo names this file, so the
#      password is never in a command line, the compose file or postgresql.auto.conf.
#   2. First start only: clones pg-primary with pg_basebackup over TLS (verify-full) using the
#      physical slot pg_replica, then marks the data directory as a standby. A marker file
#      written last makes this idempotent: a later start skips the clone, and a clone that was
#      interrupted (no marker) is wiped and redone.
#   3. Phase 4 (compose.phase4.yaml; skipped when the watcher script is not mounted): replica-side
#      deny list for revoked temp roles (config/postgres/pg-deny-watcher.sh). Writes the pg_hba
#      include file from the descriptors BEFORE the server starts (so a restart during a primary
#      outage never accepts a denied role), then starts the watcher under "tini -s" (child
#      subreaper) with a restart loop, in the background. The server is still PID 1 (exec below).
#      If any of this fails, the server still starts: the include file then holds the sentinel
#      only (no deny) and the failure is logged (alert pg_deny_watcher_failed).
set -euo pipefail

: "${PGDATA:=/var/lib/postgresql/data}"
marker="$PGDATA/replica-bootstrap.done"
passdir=/var/run/postgresql/replica
passfile="$passdir/pgpass"
primary_host=pg-primary
conninfo="host=$primary_host port=5432 user=replicator application_name=pg-replica sslmode=verify-full sslrootcert=/pki-ca/ca.crt passfile=$passfile"

install -d -o postgres -g postgres -m 0700 "$passdir"
(
    umask 077
    # host:port:database:user:password; "replication" connections match database "replication".
    printf '%s:5432:replication:replicator:%s\n' "$primary_host" "$(cat /run/secrets/pg_replicator_password)" > "$passfile"
)
chown postgres:postgres "$passfile"
chmod 0600 "$passfile"

if [ -f "$marker" ]; then
    echo "pg-replica: data directory already bootstrapped ($(cat "$marker")); starting as standby"
else
    mkdir -p "$PGDATA"
    chown postgres:postgres "$PGDATA"
    chmod 0700 "$PGDATA"
    tries=0
    until {
        # Anything left over is an interrupted clone: start from an empty directory.
        find "$PGDATA" -mindepth 1 -delete
        echo "pg-replica: pg_basebackup from $primary_host (slot pg_replica, sslmode=verify-full)"
        gosu postgres pg_basebackup -d "$conninfo" -D "$PGDATA" -X stream -S pg_replica -c fast --no-password
    }; do
        tries=$((tries + 1))
        if [ "$tries" -ge 20 ]; then echo "pg-replica: pg_basebackup failed $tries times, giving up" >&2; exit 1; fi
        echo "pg-replica: pg_basebackup failed (attempt $tries), retrying in 3 s" >&2
        sleep 3
    done
    gosu postgres touch "$PGDATA/standby.signal"
    date -u +"cloned %Y-%m-%dT%H:%M:%SZ" | gosu postgres tee "$marker" > /dev/null
    echo "pg-replica: clone complete, standby.signal written"
fi

watcher=/opt/replica/pg-deny-watcher.sh
if [ -f "$watcher" ]; then
    deny_work=/var/lib/postgresql/pg-deny
    install -d -o postgres -g postgres -m 0700 "$deny_work"
    # Log directory on the replica's log volume (group 4000 = the shipper, setgid like its parent).
    install -d -o postgres -g 4000 -m 2750 /var/log/pgaudit/pg-deny
    if ! gosu postgres bash "$watcher" apply-offline; then
        echo "pg-replica: pg-deny apply-offline failed" >&2
    fi
    # pg_hba.conf includes this file; a missing or token-less file would stop the server.
    if [ ! -s "$deny_work/denied_roles" ]; then
        printf '%s\n' '/^$' > "$deny_work/denied_roles"
        chown postgres:postgres "$deny_work/denied_roles"
        chmod 0600 "$deny_work/denied_roles"
    fi
    if command -v tini > /dev/null; then
        gosu postgres tini -s -- bash "$watcher" supervise &
    else
        echo "pg-replica: tini missing, pg-deny watcher NOT started" >&2
        printf '%s engine=postgresql action=error reason=tini-missing outcome=failed detail="pg-deny watcher not started"\n' "$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)" | gosu postgres tee -a /var/log/pgaudit/pg-deny/pg-deny-watcher.log > /dev/null
    fi
fi

exec docker-entrypoint.sh "$@"
