#!/bin/bash
# Phase 3: entrypoint of maria-replica (compose.phase3.yaml). Runs as root before the image's
# docker-entrypoint.sh. The seed (/docker-entrypoint-initdb.d/20-replica-seed.sh) runs only when
# the data directory is empty. If a seed was interrupted, the image would see an initialized
# data directory on the next start and skip init, leaving a replica without data or replication.
# The seed script creates .replica-seed-incomplete first and deletes it last; if it is still
# there, the data directory is wiped here so the next start seeds again from scratch.
set -euo pipefail

datadir=/var/lib/mysql
if [ -e "$datadir/.replica-seed-incomplete" ]; then
    echo "maria-replica: an earlier seed did not finish; wiping $datadir to seed again" >&2
    find "$datadir" -mindepth 1 -delete
fi

exec docker-entrypoint.sh "$@"
