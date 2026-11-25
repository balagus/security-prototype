#!/bin/bash
# Replica-side deny list for revoked PostgreSQL temp roles (runs inside pg-replica as
# postgres; started by config/postgres/replica-entrypoint.sh).
#
# The gap: while pg-primary is down, OpenBao cannot DROP a revoked temp role and the standby
# cannot either (read-only), so the role kept logging in to pg-replica until its VALID UNTIL
# (lease end: 1 h default, up to max_ttl 4 h), and its open sessions stayed. Expiry needs nothing
# here: VALID UNTIL replicates and the standby enforces it.
#
# Channel (one writer, one reader, no network, no credential):
#   lease-reconciler writes, for every PostgreSQL lease whose revocation is pending (TTL <= 0) or
#   irrevocable, one descriptor into the volume pg-deny (read-write there, READ-ONLY here):
#     name  <OpenBao role>.<lease id suffix>.deny
#     body  "v1 <OpenBao role> <lease issue_time in unix seconds>\n"      (nothing else)
#   This script validates every descriptor strictly and turns each valid one into a regular
#   expression for the temp role names that lease can have. The username template
#   (scripts/setup-access.ps1) is  v-<display name, max 30>-<role name, max 12>-<unix_time>-<random 4>;
#   unix_time is taken when the name is generated, just BEFORE the lease is created, so it is the
#   lease's issue second or slightly earlier (measured: 0 s in 29 of 30, 1 s in 1 of 30). Pattern:
#     ^v-.+-<role, first 12 chars>-(<issued-W>|...|<issued>)-[A-Za-z0-9]{4}$      (W: window)
#   The patterns go to OUT (below; container file system, owner postgres, mode 0600; the
#   reconciler cannot reach it), which pg_hba.conf includes in a static line placed before every
#   allow line:
#     host all @/var/lib/postgresql/pg-deny/denied_roles all reject
#   Measured on PostgreSQL 17: regular expressions work inside an @file; an @file without any
#   token (empty or only comments) is a parse error (FATAL at server start, "not reloaded" on
#   SIGHUP), hence the first token is the sentinel /^$ which matches no role name; a broken file
#   is never loaded on reload (the previous rules stay); "all", "+group", "@file" and commas in the
#   file are interpreted, and double quotes do NOT turn a /regex into a literal there. So nothing
#   from a descriptor reaches OUT except the validated role name (a-z 0-9 _ -) and digits.
#   Every pattern starts with ^v-, so it can never match replicator, session_sweeper, bao_admin,
#   postgres or any other account that is not a temp user.
#
# Modes:
#   apply-offline  no server needed: write OUT from the descriptors and the saved state. Run by the
#                  entrypoint BEFORE the server starts, so a restart during an outage never
#                  accepts a denied role, not even briefly.
#   watch          the loop: every PG_DENY_INTERVAL_SECONDS scan, rewrite OUT when the set changes,
#                  reload (pg_ctl reload = SIGHUP, works on a standby), terminate the sessions of
#                  matching roles (local socket, as postgres), log. SQL runs only while entries
#                  exist (no idle logins).
#   supervise      runs "watch" and restarts it when it exits (each restart is logged and
#                  alerted). Started by the entrypoint as  tini -s -- <this> supervise  so that the
#                  postmaster (PID 1) is never the parent of anything the watcher forks: PostgreSQL
#                  17 treats ANY unknown child that dies by a signal or with an exit code other than
#                  0/1 as a crashed backend and restarts every session (measured).
#
# Release: an entry whose descriptor is gone (the reconciler removes it once OpenBao has no lease,
# i.e. after DROP ROLE ran on the primary) stays until no role matches it any more (the DROP has
# replicated), or, for a role that still matches (another role issued in the same seconds, or a
# lease removed without revocation), PG_DENY_RELEASE_GRACE_SECONDS after the removal while the
# standby is streaming. An entry is never released while the descriptor directory is unreadable.
#
# One line per action to LOG (shipped by Fluent Bit, alert rules in config/fluent-bit/audit.lua):
#   <time> engine=postgresql action=<a> [descriptor=<key>] [role=..] [users=..] ... [detail="..."]
# Names and reasons only; a descriptor's content is never logged.
set -u
export LC_ALL=C
umask 027

num() { case "$1" in ''|*[!0-9]*) echo "$2" ;; *) echo "$1" ;; esac; }
mode="${1:-watch}"
self="$(readlink -f "$0")"
src="${PG_DENY_DIR:-/pg-deny}"
work="${PG_DENY_WORK_DIR:-/var/lib/postgresql/pg-deny}"
logdir="${PG_DENY_LOG_DIR:-/var/log/pgaudit/pg-deny}"
out="$work/denied_roles"
statef="$work/state"
hb="$work/heartbeat"
logf="$logdir/pg-deny-watcher.log"
interval="$(num "${PG_DENY_INTERVAL_SECONDS:-}" 2)"
grace="$(num "${PG_DENY_RELEASE_GRACE_SECONDS:-}" 60)"
win="$(num "${PG_DENY_TS_WINDOW_SECONDS:-}" 3)"; [ "$win" -le 10 ] || win=10
trunc="$(num "${PG_DENY_ROLE_TRUNCATE:-}" 12)"; [ "$trunc" -ge 1 ] || trunc=12
max_files="$(num "${PG_DENY_MAX_DESCRIPTORS:-}" 100)"
recheck="$(num "${PG_DENY_RECHECK_SECONDS:-}" 30)"
: "${PGDATA:=/var/lib/postgresql/data}"
conn="dbname=postgres application_name=pg-deny-watcher connect_timeout=3"
SENTINEL='/^$'
US=$'\x1f'

role_re='^[a-z0-9][a-z0-9_-]{0,63}$'
name_re='^([a-z0-9][a-z0-9_-]{0,63})\.([A-Za-z0-9]{1,64})\.deny$'
body_re=$'^v1 ([a-z0-9][a-z0-9_-]{0,63}) ([1-9][0-9]{9})\n$'
state_re='^([a-z0-9][a-z0-9_-]{0,63}\.[A-Za-z0-9]{1,64}) ([a-z0-9][a-z0-9_-]{0,63}) ([1-9][0-9]{9}) ([0-9]{1,10}) ([01])$'

ts() { date -u +%Y-%m-%dT%H:%M:%S.%3NZ; }
log() { local l; l="$(ts) engine=postgresql $*"; printf '%s\n' "$l" >> "$logf" 2>/dev/null; printf '%s\n' "$l"; }
# Attacker-controlled text (file names) for the log: safe characters only, bounded.
clean() { printf '%s' "$1" | tr -c 'A-Za-z0-9._-' '?' | cut -c1-80; }
oneline() { tr '\n\r\t"' '    ' | sed -e 's/  */ /g' -e 's/^ //' | cut -c1-200; }

# The OpenBao roles this replica accepts descriptors for (exact names).
allowed=' '
for r in ${PG_DENY_ALLOWED_ROLES:-}; do [[ $r =~ $role_re ]] && allowed="$allowed$r "; done

pattern() {
    local r="${1:0:$trunc}" t="$2" alts='' i
    for ((i = win; i >= 0; i--)); do alts="${alts:+$alts|}$((t - i))"; done
    printf '^v-.+-%s-(%s)-[A-Za-z0-9]{4}$' "$r" "$alts"
}

declare -A E_role=() E_ts=() E_rm=() E_lg=() D_role=() D_ts=() REJ=()
load_state() {
    E_role=(); E_ts=(); E_rm=(); E_lg=()
    [ -f "$statef" ] || return 0
    local line
    while IFS= read -r line; do
        [[ $line =~ $state_re ]] || continue
        local k="${BASH_REMATCH[1]}"
        E_role[$k]="${BASH_REMATCH[2]}"; E_ts[$k]="${BASH_REMATCH[3]}"; E_rm[$k]="${BASH_REMATCH[4]}"; E_lg[$k]="${BASH_REMATCH[5]}"
    done < "$statef"
}
save_state() {
    local k tmp="$statef.tmp"
    { for k in "${!E_role[@]}"; do printf '%s %s %s %s %s\n' "$k" "${E_role[$k]}" "${E_ts[$k]}" "${E_rm[$k]}" "${E_lg[$k]}"; done; } > "$tmp" && chmod 0600 "$tmp" && mv -f "$tmp" "$statef"
}

reject() {
    # $1 file name, $2 reason, $3 signature (logged once per file version)
    local sig
    sig="$(clean "$1")|$3"
    [ -n "${REJ[$sig]:-}" ] && return 0
    REJ[$sig]=1
    log "action=descriptor-rejected descriptor=$(clean "$1") reason=$2 outcome=ignored"
}

# Fills D_role / D_ts from the valid descriptors. scan_ok=0 if the directory cannot be read (then
# nothing is released).
scan() {
    D_role=(); D_ts=(); scan_ok=1
    if [ ! -d "$src" ] || [ ! -r "$src" ] || [ ! -x "$src" ]; then scan_ok=0; return 0; fi
    local f b sig c n=0 now crole cts
    now="$(date +%s)"
    shopt -s nullglob
    # Dot files are never read: the reconciler writes .tmp.* and renames (atomic).
    for f in "$src"/*; do
        b="${f##*/}"
        sig="$(stat -c '%s.%Y.%i' -- "$f" 2>/dev/null)"
        n=$((n + 1))
        if [ "$n" -gt "$max_files" ]; then reject "$b" too-many-descriptors "$sig"; continue; fi
        if [ -L "$f" ]; then reject "$b" symlink "$sig"; continue; fi
        if [ ! -f "$f" ]; then reject "$b" not-a-regular-file "$sig"; continue; fi
        if [[ ! $b =~ $name_re ]]; then reject "$b" bad-name "$sig"; continue; fi
        local nrole="${BASH_REMATCH[1]}" key="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}"
        # At most 129 bytes, never following a symlink, never blocking (FIFO swapped in), NUL
        # bytes made visible; the strict pattern below then accepts one exact line only.
        c="$( { timeout 2 dd if="$f" iflag=nofollow,nonblock bs=129 count=1 status=none 2>/dev/null || printf '?read-failed'; } | tr '\000' '?'; printf x)"
        c="${c%x}"
        if [[ ! $c =~ $body_re ]]; then reject "$b" bad-content "$sig"; continue; fi
        crole="${BASH_REMATCH[1]}"; cts="${BASH_REMATCH[2]}"
        if [ "$crole" != "$nrole" ]; then reject "$b" role-mismatch "$sig"; continue; fi
        case "$allowed" in *" $crole "*) ;; *) reject "$b" role-not-allowed "$sig"; continue ;; esac
        if [ "$cts" -gt $((now + 300)) ]; then reject "$b" issued-in-future "$sig"; continue; fi
        D_role[$key]="$crole"; D_ts[$key]="$cts"
    done
    shopt -u nullglob
}

# Descriptors into entries. Sets changed=1 when the pattern set grows or changes.
merge() {
    local k now
    now="$(date +%s)"
    changed=0
    for k in "${!D_role[@]}"; do
        if [ -z "${E_role[$k]:-}" ] || [ "${E_role[$k]}" != "${D_role[$k]}" ] || [ "${E_ts[$k]}" != "${D_ts[$k]}" ]; then
            E_role[$k]="${D_role[$k]}"; E_ts[$k]="${D_ts[$k]}"; E_rm[$k]=0; E_lg[$k]=0; changed=1
        elif [ "${E_rm[$k]}" != 0 ]; then
            E_rm[$k]=0
            log "action=descriptor-back descriptor=$k role=${E_role[$k]} issued=${E_ts[$k]} outcome=held"
        fi
    done
    [ "$scan_ok" = 1 ] || return 0
    for k in "${!E_role[@]}"; do
        if [ -z "${D_role[$k]:-}" ] && [ "${E_rm[$k]}" = 0 ]; then
            E_rm[$k]="$now"
            log "action=descriptor-gone descriptor=$k role=${E_role[$k]} issued=${E_ts[$k]} outcome=held detail=\"kept until no role matches, or ${grace} s while streaming\""
        fi
    done
}

render() {
    local k
    printf '# Generated by pg-deny-watcher.sh (pg-replica). Do not edit. The first token matches no role.\n'
    printf '%s\n' "$SENTINEL"
    for k in "${!E_role[@]}"; do printf '/%s\n' "$(pattern "${E_role[$k]}" "${E_ts[$k]}")"; done | sort -u
}

# Writes OUT atomically if its content differs. Returns 0 written, 1 unchanged, 2 failed.
prev=''
write_file() {
    local new cur tmp="$out.tmp"
    new="$(render)"
    cur="$(cat "$out" 2>/dev/null)"
    if [ -f "$out" ] && [ "$new" = "$cur" ]; then return 1; fi
    prev="$cur"
    if printf '%s\n' "$new" > "$tmp" && chmod 0600 "$tmp" && mv -f "$tmp" "$out"; then return 0; fi
    rm -f "$tmp"
    return 2
}

sql() {
    # $1 SQL (may use :'pats'), $2 space-separated patterns. Fields separated by US (0x1f): the
    # patterns contain "|". Local socket, peer authentication as postgres.
    printf '%s\n' "$1" | psql -X -q -At -F "$US" -v ON_ERROR_STOP=1 -v "pats=$2" "$conn" 2>&1
}

# After a rewrite: check the file parses (pg_hba_file_rules re-reads it), then SIGHUP.
apply_file() {
    local v rc
    v="$(sql "SELECT 'V', count(*) FILTER (WHERE error IS NOT NULL), coalesce(string_agg(error, '; '), '') FROM pg_hba_file_rules" '')"
    rc=$?
    if [ $rc -eq 0 ] && [[ $v =~ ^V${US}([0-9]+)${US} ]] && [ "${BASH_REMATCH[1]}" != 0 ]; then
        printf '%s\n' "$prev" > "$out.tmp" && chmod 0600 "$out.tmp" && mv -f "$out.tmp" "$out"
        log "action=reload-failed outcome=failed detail=\"pg_hba_file_rules: $(printf '%s' "$v" | oneline); previous file restored\""
        return 1
    fi
    reload || return 2
    return 0
}
reload() {
    local v
    v="$(pg_ctl reload -s -D "$PGDATA" 2>&1)"
    if [ $? -ne 0 ]; then
        if [ "$reload_pending" = 0 ]; then log "action=reload-pending outcome=pending detail=\"$(printf '%s' "$v" | oneline) (retried every pass; a starting server reads the file itself)\""; fi
        reload_pending=1
        return 1
    fi
    [ "$reload_pending" = 1 ] && log "action=reload-done outcome=ok"
    reload_pending=0
    return 0
}

# watch-mode state
term_again=0; last_sql=0; sql_err=''; dir_err=''; reload_pending=0

pass() {
    local now k rows line kind a b c pats='' n_rm=0 n_unl=0 status='unknown' released=0
    now="$(date +%s)"
    if [ "$reload_pending" = 1 ]; then reload && term_again=2; fi
    scan
    if [ "$scan_ok" = 0 ]; then
        if [ "$dir_err" != 1 ]; then dir_err=1; log "action=error reason=descriptor-dir-unreadable outcome=failed detail=\"$src is missing or unreadable: no new denies; existing entries are kept\""; fi
    elif [ "$dir_err" = 1 ]; then dir_err=0; log "action=recovered detail=\"$src readable again\""; fi
    merge
    if [ "$changed" = 1 ]; then
        write_file; local w=$?
        if [ $w -eq 0 ]; then apply_file; term_again=2; elif [ $w -eq 2 ]; then log "action=error reason=write-failed outcome=failed detail=\"cannot write $out\""; fi
    fi
    for k in "${!E_role[@]}"; do
        pats="$pats $(pattern "${E_role[$k]}" "${E_ts[$k]}")"
        [ "${E_rm[$k]}" != 0 ] && n_rm=$((n_rm + 1))
        [ "${E_lg[$k]}" = 0 ] && n_unl=$((n_unl + 1))
    done
    pats="${pats# }"
    if [ -n "$pats" ] && { [ "$term_again" -gt 0 ] || [ "$n_rm" -gt 0 ] || [ "$n_unl" -gt 0 ] || [ $((now - last_sql)) -ge "$recheck" ]; }; then
        # One connection: terminate matching sessions, then list matching roles and the receiver.
        rows="$(sql "SELECT 'T', a.pid, a.usename, pg_terminate_backend(a.pid) FROM pg_stat_activity a WHERE a.pid <> pg_backend_pid() AND a.usename ~ ANY (string_to_array(:'pats', ' '));
SELECT 'M', p, count(r.oid), coalesce(string_agg(r.rolname::text, ',' ORDER BY r.rolname), '') FROM unnest(string_to_array(:'pats', ' ')) p LEFT JOIN pg_roles r ON r.rolname ~ p GROUP BY p;
SELECT 'S', coalesce((SELECT status FROM pg_stat_wal_receiver), 'none');" "$pats")"
        if [ $? -ne 0 ]; then
            local e; e="$(printf '%s' "$rows" | oneline)"
            if [ "$e" != "$sql_err" ]; then sql_err="$e"; log "action=sql-unavailable outcome=pending detail=\"$e\""; fi
        else
            [ -n "$sql_err" ] && { sql_err=''; log "action=sql-recovered"; }
            last_sql="$now"
            [ "$term_again" -gt 0 ] && term_again=$((term_again - 1))
            declare -A M_n=() M_u=() T_n=()
            while IFS="$US" read -r kind a b c; do
                case "$kind" in
                    T) local tk=''
                       for k in "${!E_role[@]}"; do [[ $b =~ $(pattern "${E_role[$k]}" "${E_ts[$k]}") ]] && { tk="$k"; break; }; done
                       [ -n "$tk" ] && T_n[$tk]=$(( ${T_n[$tk]:-0} + 1 ))
                       log "action=terminated pid=$a role=$b descriptor=$tk outcome=$([ "$c" = t ] && echo ok || echo failed)" ;;
                    M) M_n[$a]="$b"; M_u[$a]="$c" ;;
                    S) status="$a" ;;
                esac
            done <<< "$rows"
            for k in "${!E_role[@]}"; do
                local p; p="$(pattern "${E_role[$k]}" "${E_ts[$k]}")"
                local m="${M_n[$p]:-0}" u="${M_u[$p]:-}"
                if [ "${E_lg[$k]}" = 0 ]; then
                    E_lg[$k]=1
                    log "action=deny-applied descriptor=$k role=${E_role[$k]} issued=${E_ts[$k]} users=${u:--} matched=$m terminated=${T_n[$k]:-0} over_deny=$([ "$m" -gt 1 ] && echo 1 || echo 0) receiver=$status pattern=/$p outcome=ok"
                fi
                if [ "${E_rm[$k]}" != 0 ]; then
                    local why=''
                    if [ "$m" = 0 ]; then why=no-matching-role
                    elif [ $((now - ${E_rm[$k]})) -ge "$grace" ] && [ "$status" = streaming ]; then why=grace-expired-while-streaming; fi
                    if [ -n "$why" ]; then
                        log "action=deny-released descriptor=$k role=${E_role[$k]} issued=${E_ts[$k]} users=${u:--} matched=$m reason=$why receiver=$status outcome=ok"
                        unset "E_role[$k]" "E_ts[$k]" "E_rm[$k]" "E_lg[$k]"
                        released=1
                    fi
                fi
            done
        fi
    fi
    if [ "$released" = 1 ]; then
        write_file; local w=$?
        if [ $w -eq 0 ]; then apply_file; fi
        if [ ${#E_role[@]} -eq 0 ]; then log "action=deny-list-empty outcome=ok detail=\"only the sentinel is left in $out\""; fi
    fi
    save_state
}

case "$mode" in
    apply-offline)
        mkdir -p "$work" "$logdir" 2>/dev/null
        load_state
        scan
        [ "$scan_ok" = 1 ] || log "action=error reason=descriptor-dir-unreadable outcome=failed detail=\"$src is missing or unreadable at start: only saved entries are applied\""
        merge
        write_file; w=$?
        if [ $w -eq 2 ] || [ ! -s "$out" ]; then
            printf '%s\n' "$SENTINEL" > "$out" && chmod 0600 "$out"
            log "action=error reason=write-failed outcome=failed detail=\"wrote the sentinel only\""
        fi
        save_state
        log "action=startup-apply entries=${#E_role[@]} descriptors=${#D_role[@]} outcome=ok detail=\"written before the server starts\""
        exit 0
        ;;
    watch)
        mkdir -p "$work" "$logdir" 2>/dev/null
        load_state
        # Entries restored from the state (container restart): terminate and resolve once.
        [ ${#E_role[@]} -gt 0 ] && term_again=1
        log "action=watcher-start interval=${interval}s window=${win}s grace=${grace}s allowed_roles=$(echo $allowed | tr ' ' ',') entries=${#E_role[@]}"
        # The file must reflect the saved state (normally apply-offline already wrote it).
        if write_file; then apply_file; term_again=2; fi
        # On SIGTERM (from the supervisor) finish the current command, wait for the sleep, exit 0:
        # nothing may be left behind for the postmaster to reap with a signal status.
        trap 'wait; exit 0' TERM INT
        while :; do
            pass
            touch "$hb"
            sleep "$interval" & wait $!
        done
        ;;
    supervise)
        child=''
        trap '' HUP
        # Stop the watcher and WAIT for it (and any sleep) before exiting 0. Without the wait, tini
        # exited first and the dying watcher was reaped by the postmaster ("terminated by signal 15"),
        # which restarted every session (measured, intermittent).
        trap 'log "action=supervisor-stopped outcome=failed detail=\"supervisor got a signal: the deny list is no longer maintained; the current file stays in effect\""; [ -n "$child" ] && kill "$child" 2>/dev/null; wait; exit 0' TERM INT
        log "action=supervisor-start pid=$$"
        restarts=0; delay=1
        while :; do
            started="$(date +%s)"
            bash "$self" watch &
            child=$!
            wait "$child"; rc=$?
            child=''
            restarts=$((restarts + 1))
            if [ $(( $(date +%s) - started )) -ge 60 ]; then delay=1; fi
            log "action=watcher-restarted rc=$rc restarts=$restarts outcome=failed detail=\"the watcher exited; restarting in ${delay} s\""
            sleep "$delay" & wait $!
            [ "$delay" -lt 30 ] && delay=$((delay * 2))
        done
        ;;
    *)
        echo "usage: $0 apply-offline|watch|supervise" >&2
        exit 2
        ;;
esac
