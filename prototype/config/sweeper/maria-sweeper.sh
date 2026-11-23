#!/bin/bash
# Phase 3: MariaDB replica session sweeper (design 5.4). Runs in a mariadb:11.8 container
# (client only) on the access network at a fixed address, as account session_sweeper
# (PROCESS, CONNECTION ADMIN, SELECT (User) ON mysql.user), over TLS with server certificate
# verification.
#
# Every SWEEP_INTERVAL_SECONDS it kills connections on the replica whose user name starts with
# "v-" (OpenBao temp users) and no longer exists as an account: DROP USER replicates, but KILL
# does not, and a dropped account's open connection keeps running.
# It never touches other connections: replication threads ("system user"), the application
# and OpenBao accounts, root, or its own connection (its name does not start with "v-").
# Each kill is logged as one line: timestamp, engine, connection id, user, client host.
# The password is read from the Docker secret into a defaults file on tmpfs.
set -uo pipefail

interval="${SWEEP_INTERVAL_SECONDS:-60}"
target="${SWEEP_TARGET_HOST:-maria-replica}"
cnf=/tmp/sweeper.cnf
(umask 077; printf '[client]\nuser=session_sweeper\npassword=%s\nhost=%s\nport=3306\nssl-ca=/pki-ca/ca.crt\nssl-verify-server-cert\nconnect-timeout=5\n' \
    "$(cat /run/secrets/maria_session_sweeper_password)" "$target" > "$cnf")

ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }
log() { echo "$(ts) engine=mariadb $*"; }

# LIKE 'v-%': "-" is not a wildcard; "_" would be, and is not used.
list_sql="SELECT p.ID, p.USER, p.HOST FROM information_schema.PROCESSLIST p
WHERE p.USER LIKE 'v-%' AND p.ID <> CONNECTION_ID()
  AND NOT EXISTS (SELECT 1 FROM mysql.user u WHERE u.User = p.USER)"

log "action=start target=$target interval=${interval}s"
last_err=''
while true; do
    out="$(mariadb --defaults-extra-file="$cnf" -N -B -e "$list_sql" 2>&1)"
    rc=$?
    if [ $rc -ne 0 ]; then
        err="$(echo "$out" | tr '\n' ' ')"
        if [ "$err" != "$last_err" ]; then log "action=error detail=\"$err\""; last_err="$err"; fi
    else
        if [ -n "$last_err" ]; then log "action=recovered"; last_err=''; fi
        while IFS=$'\t' read -r id user host; do
            [ -n "$id" ] || continue
            # Connection ids are never reused while the server runs, so no re-check is needed.
            res="$(mariadb --defaults-extra-file="$cnf" -N -B -e "KILL CONNECTION $id" 2>&1)"
            if [ -z "$res" ]; then
                log "action=killed id=$id user=$user host=$host reason=account-dropped"
            else
                log "action=kill-failed id=$id user=$user host=$host detail=\"$(echo "$res" | tr '\n' ' ')\""
            fi
        done <<< "$out"
    fi
    sleep "$interval"
done
