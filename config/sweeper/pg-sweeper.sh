#!/bin/bash
# PostgreSQL replica session sweeper (docs/DECISIONS.md D7). Runs in a postgres:17 container
# (client tools only) on the access network at a fixed address, as role session_sweeper
# (pg_signal_backend + CONNECT on app1, nothing else), over TLS with sslmode=verify-full.
#
# Every SWEEP_INTERVAL_SECONDS it terminates client sessions on the replica whose
#   (a) role no longer exists: after a replicated DROP ROLE the session keeps running and its
#       usename in pg_stat_activity is NULL, so it is matched by usesysid missing from pg_roles;
#   (b) role is a temp user (name "v-...") whose VALID UNTIL has passed (a lease that expired
#       but whose revocation has not reached the replica, or failed).
# It never touches processes without a role (walreceiver, startup, checkpointer, ...: their
# usesysid is NULL), its own session, or any session whose role still exists and is not an
# expired v- role (applications, replicator, bao_admin, superuser).
# backend_type is deliberately NOT used: without pg_read_all_stats, pg_stat_activity shows
# backend_type (and backend_start, state, query, client_addr) as NULL for other roles'
# sessions, so "backend_type = 'client backend'" would silently match nothing. pid and
# usesysid are visible to every role, which is all this needs.
# Each kill is logged as one line: timestamp, engine, pid, usesysid, role, reason.
# The password is read from the Docker secret into a passfile on tmpfs, never into argv/env.
set -uo pipefail

interval="${SWEEP_INTERVAL_SECONDS:-60}"
target="${SWEEP_TARGET_HOST:-pg-replica}"
export PGPASSFILE=/tmp/pgpass
(umask 077; printf '%s:5432:app1:session_sweeper:%s\n' "$target" "$(cat /run/secrets/pg_session_sweeper_password)" > "$PGPASSFILE")
conn="host=$target port=5432 dbname=app1 user=session_sweeper sslmode=verify-full sslrootcert=/pki-ca/ca.crt connect_timeout=5 application_name=pg-sweeper"

ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }
log() { echo "$(ts) engine=postgresql $*"; }

# The victim condition. Used twice: to list candidates, and again inside the terminating
# statement, so a pid that was reused in between by a legitimate session is not killed.
cond="a.pid <> pg_backend_pid()
  AND a.usesysid IS NOT NULL
  AND (r.oid IS NULL OR (r.rolname LIKE 'v-%' AND r.rolvaliduntil < now()))"

list_sql="SELECT a.pid, a.usesysid, coalesce(r.rolname, '-'),
       CASE WHEN r.oid IS NULL THEN 'role-dropped' ELSE 'valid-until-passed' END
FROM pg_stat_activity a LEFT JOIN pg_roles r ON r.oid = a.usesysid
WHERE $cond"

log "action=start target=$target interval=${interval}s"
last_err=''
while true; do
    out="$(psql "$conn" -X -At -F '|' -v ON_ERROR_STOP=1 -c "$list_sql" 2>&1)"
    rc=$?
    if [ $rc -ne 0 ]; then
        err="$(echo "$out" | tr '\n' ' ')"
        # Log a repeated error once, not every interval.
        if [ "$err" != "$last_err" ]; then log "action=error detail=\"$err\""; last_err="$err"; fi
    else
        if [ -n "$last_err" ]; then log "action=recovered"; last_err=''; fi
        while IFS='|' read -r pid sysid role reason; do
            [ -n "$pid" ] || continue
            res="$(psql "$conn" -X -At -v ON_ERROR_STOP=1 -c "SELECT pg_terminate_backend(a.pid) FROM pg_stat_activity a LEFT JOIN pg_roles r ON r.oid = a.usesysid WHERE a.pid = $pid AND $cond" 2>&1)"
            if [ "$res" = "t" ]; then
                log "action=terminated pid=$pid usesysid=$sysid role=$role reason=$reason"
            elif [ -n "$res" ]; then
                log "action=terminate-failed pid=$pid usesysid=$sysid role=$role reason=$reason detail=\"$(echo "$res" | tr '\n' ' ')\""
            fi
        done <<< "$out"
    fi
    sleep "$interval"
done
