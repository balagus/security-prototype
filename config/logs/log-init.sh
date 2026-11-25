#!/bin/sh
# One-shot preparation of the log volumes (compose.yaml, service log-init).
# Runs as root with no network, before every server that writes a log, and only sets ownership
# and modes. Idempotent.
#
# Model: every SOURCE log directory belongs to the uid of the one process that writes it, with
# the group AUDIT_GID (a group no image uses) and mode 2750. The setgid bit makes every new file
# in it inherit that group, and each writer creates its files group-readable (PostgreSQL
# log_file_mode=0640, OpenBao audit mode 0640, MariaDB and tee with umask 022), so the shipper,
# which runs as FLB_UID with primary group AUDIT_GID, can read them. The shipper mounts the
# source volumes read-only. Nobody else is in the group.
# The STORE (log-store) and the shipper's state belong to FLB_UID. Only the fluent-bit
# container mounts them, read-write; no database, OpenBao, application or developer-facing
# container mounts them at all.
set -eu

AUDIT_GID=4000      # log readers (the fluent-bit container's primary group)
FLB_UID=4001        # fluent-bit
DB_UID=999          # postgres in postgres:17, mysql in mariadb:11.8, also the sweepers (999:999)
BAO_UID=100         # openbao in openbao/openbao

prep_source() {
    dir="$1"; uid="$2"
    [ -d "$dir" ] || return 0
    chown "$uid:$AUDIT_GID" "$dir"
    chmod 2750 "$dir"
    # Files left from earlier starts: group AUDIT_GID, group-readable, never group-writable.
    find "$dir" -mindepth 1 -type f -exec chgrp "$AUDIT_GID" {} + -exec chmod g+r,g-w,o-rwx {} +
    echo "log-init: $dir -> owner $uid, group $AUDIT_GID, mode 2750"
}

prep_source /v/pg-primary-log "$DB_UID"
prep_source /v/pg-replica-log "$DB_UID"
prep_source /v/maria-primary-audit "$DB_UID"
prep_source /v/maria-replica-audit "$DB_UID"
prep_source /v/pg-sweeper-log "$DB_UID"
prep_source /v/maria-sweeper-log "$DB_UID"
prep_source /v/bao-audit "$BAO_UID"
# Revocation backstops: the lease reconciler runs as the openbao uid. (The MariaDB backstop
# lines go to maria-replica-audit/backstop/, created by the replica's entrypoint.)
prep_source /v/reconciler-log "$BAO_UID"
# pg-replica's deny-list log (pg-replica-log/pg-deny/) is created by its entrypoint with the same
# owner, group and mode.

# Not a log volume: the PostgreSQL deny-list descriptors (docs/DECISIONS.md D8). Written ONLY by the lease
# reconciler (openbao uid, its own group 1000), read by pg-replica (mounted read-only there).
# Mode 0755: no other uid can create, rename or remove a descriptor.
if [ -d /v/pg-deny ]; then
    chown "$BAO_UID:1000" /v/pg-deny
    chmod 0755 /v/pg-deny
    echo "log-init: /v/pg-deny -> owner $BAO_UID:1000, mode 0755 (descriptors: lease-reconciler only)"
fi

for d in /v/log-store /v/fluent-bit-state; do
    chown -R "$FLB_UID:$AUDIT_GID" "$d"
    chmod 0750 "$d"
    echo "log-init: $d -> owner $FLB_UID, mode 0750"
done
chmod 0700 /v/fluent-bit-state
echo "log-init: done"
