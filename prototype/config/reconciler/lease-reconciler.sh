#!/bin/sh
# Phase 4: OpenBao lease reconciler (design 5.4, "Revocation depends on the replica being
# reachable"). Runs in an openbao/openbao:2.7.2 container (busybox sh + the bao CLI) on the
# internal network bao-reconciler, which holds only OpenBao and this container. It reaches no
# database; it only asks OpenBao to retry revocations.
#
# Every RECONCILE_INTERVAL_SECONDS:
#   1. irrevocable leases (GET sys/leases?type=irrevocable, sudo): OpenBao gave up after 6 failed
#      revocation attempts (about 10.6 min). Each one under database/creds/ is logged once
#      (action=irrevocable-found) and then revoked with sync=true, retried with backoff until
#      the target database is reachable again (action=revoke-irrevocable).
#   2. pending revocations under database/creds/: a lease whose TTL is 0 or less (expired, or
#      revoked asynchronously while the database was down; OpenBao keeps it and retries with
#      growing, jittered delays, 6 attempts). Seen so in two consecutive passes (so a normal expiry,
#      which OpenBao revokes within a second, is never touched), it is revoked with sync=true
#      (action=revoke-retried), retried with backoff while the database is unreachable.
#   3. PostgreSQL replica deny list (design 5.4): for every lease of a role in PG_DENY_ROLES that
#      is pending (TTL <= 0, from the FIRST pass that sees it) or irrevocable, it writes a
#      descriptor into PG_DENY_DIR (volume pg-deny; only this container mounts it read-write,
#      pg-replica mounts it read-only):
#        file <role>.<lease id suffix>.deny    body "v1 <role> <lease issue_time, unix seconds>"
#      written to a dot-file and renamed (atomic). pg-replica's watcher
#      (config/postgres/pg-deny-watcher.sh) turns it into a pg_hba reject for the temp role names
#      of that lease, so a revoked role is refused on the replica while the primary is down.
#      A descriptor is removed once OpenBao reports the lease gone ("invalid lease") or valid
#      again (TTL > 0); never on any other error. MariaDB leases never get one (their temp users
#      live on maria-replica, which OpenBao revokes directly; startup purge covers its restarts).
#      The issue time is the only extra field it reads (sys/leases/lookup, already allowed).
# Valid leases (TTL > 0) are never touched: a "bao lease revoke -sync" that failed leaves a
# valid lease, which this loop cannot tell from any other valid lease.
# Backoff per lease after a failed attempt: wait 1, 2, 4, ... passes, at most
# RECONCILE_MAX_BACKOFF_PASSES.
#
# One line per action on stdout (tee'd to a file that Fluent Bit ships):
#   <time> engine=openbao-reconciler action=<a> lease=<lease id> role=<role> outcome=<ok|failed> [detail="..."]
#
# Authentication: AppRole lease-reconciler (scripts/phase4-setup.ps1). role_id and secret_id are
# Docker secrets (files under secrets\), passed to the bao CLI as role_id=@file, so they never
# appear in a command line or the environment. The batch token lives only in a shell variable
# and in the environment of each bao child process (not in argv, not in a file); it is bound to
# this container's address and can only list, look up and revoke leases (config/openbao/
# lease-reconciler.hcl).
#
# Usage: lease-reconciler.sh            the loop
#        lease-reconciler.sh bao ARGS   log in once and run "bao ARGS" with the reconciler's token
#                                       (tests\revocation-checks.ps1 uses it to show refusals)
set -u

interval="${RECONCILE_INTERVAL_SECONDS:-60}"
max_backoff="${RECONCILE_MAX_BACKOFF_PASSES:-4}"
prefix="database/creds/"
role_id_file=/run/secrets/openbao_reconciler_role_id
secret_id_file=/run/secrets/openbao_reconciler_secret_id
# The batch token's TTL is 300 s (AppRole role); log in again well before it ends.
relogin_after="${RECONCILE_RELOGIN_SECONDS:-240}"
state=/tmp/reconciler
mkdir -p "$state"
# PostgreSQL deny-list descriptors (empty PG_DENY_ROLES: feature off).
pg_deny_dir="${PG_DENY_DIR:-/pg-deny}"
pg_deny_roles=" ${PG_DENY_ROLES:-} "
umask 022

ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }
log() { echo "$(ts) engine=openbao-reconciler $*"; }
oneline() { tr '\n\r\t' '   ' | sed -e "s/\"/'/g" -e 's/  */ /g' -e 's/^ //' | cut -c1-240; }
key() { echo "$1" | tr '/.' '__'; }
role_of() { echo "$1" | sed -n 's#^database/creds/\([^/]*\)/.*#\1#p'; }
json_strings() { sed -n 's/^ *"\([^"]*\)",\{0,1\}$/\1/p'; }

token=''
token_at=0
login() {
    out="$(bao write -format=json auth/approle/login role_id=@"$role_id_file" secret_id=@"$secret_id_file" 2>&1)"
    rc=$?
    t="$(printf '%s\n' "$out" | sed -n 's/^ *"client_token": *"\([^"]*\)".*/\1/p' | head -n 1)"
    if [ $rc -ne 0 ] || [ -z "$t" ]; then
        token=''
        login_err="$(printf '%s' "$out" | oneline)"
        return 1
    fi
    token="$t"
    token_at="$(date +%s)"
    return 0
}
b() { BAO_TOKEN="$token" bao "$@"; }

if [ "${1:-}" = "bao" ]; then
    shift
    if ! login; then echo "login failed: $login_err" >&2; exit 1; fi
    b "$@"
    exit $?
fi

# Backoff state per lease: "<failures> <next pass>".
due() {
    f="$state/fail.$(key "$1")"
    [ -f "$f" ] || return 0
    read -r _n next < "$f"
    [ "$pass" -ge "$next" ]
}
record_fail() {
    f="$state/fail.$(key "$1")"
    n=0
    if [ -f "$f" ]; then read -r n _x < "$f"; fi
    n=$((n + 1))
    w=1; i=1
    while [ "$i" -lt "$n" ] && [ "$w" -lt "$max_backoff" ]; do w=$((w * 2)); i=$((i + 1)); done
    [ "$w" -gt "$max_backoff" ] && w="$max_backoff"
    echo "$n $((pass + w))" > "$f"
}

# Lease lookup: l_ttl and l_issued (issue_time as unix seconds; empty if not parseable).
lookup() {
    l_out="$(b write -format=json sys/leases/lookup lease_id="$1" 2>&1)"
    if [ $? -ne 0 ]; then l_err="$(printf '%s' "$l_out" | oneline)"; l_ttl=''; l_issued=''; return 1; fi
    l_ttl="$(printf '%s\n' "$l_out" | sed -n 's/^ *"ttl": *\(-\{0,1\}[0-9][0-9]*\).*/\1/p' | head -n 1)"
    it="$(printf '%s\n' "$l_out" | sed -n 's/^ *"issue_time": *"\([0-9][0-9-]*T[0-9:]*\)[.0-9]*Z".*/\1/p' | head -n 1)"
    l_issued=''
    if [ -n "$it" ]; then l_issued="$(date -u -D '%Y-%m-%dT%H:%M:%S' -d "$it" +%s 2>/dev/null)"; fi
    case "$l_issued" in ''|*[!0-9]*) l_issued='' ;; esac
    return 0
}
deny_role() { case "$pg_deny_roles" in *" $1 "*) return 0 ;; esac; return 1; }
suffix_of() { echo "$1" | sed -n 's#^database/creds/[a-z0-9_-]*/\([A-Za-z0-9]\{1,64\}\)$#\1#p'; }
# $1 lease id; uses l_issued from the lookup just made. Records the lease in deny.now.
deny_write() {
    r="$(role_of "$1")"
    deny_role "$r" || return 0
    sfx="$(suffix_of "$1")"
    [ -n "$sfx" ] || return 0
    echo "$r.$sfx" >> "$state/deny.now"
    f="$pg_deny_dir/$r.$sfx.deny"
    if [ -z "$l_issued" ]; then
        [ -f "$f" ] || log "action=pg-deny-written lease=$1 role=$r outcome=failed detail=\"no issue_time in the lease lookup\""
        return 0
    fi
    line="v1 $r $l_issued"
    if [ -f "$f" ] && [ "$(cat "$f" 2>/dev/null)" = "$line" ]; then return 0; fi
    tmp="$pg_deny_dir/.tmp.$r.$sfx"
    if res="$( { printf '%s\n' "$line" > "$tmp" && mv -f "$tmp" "$f"; } 2>&1)"; then
        log "action=pg-deny-written lease=$1 role=$r issued=$l_issued outcome=ok"
    else
        rm -f "$tmp"
        log "action=pg-deny-written lease=$1 role=$r outcome=failed detail=\"$(printf '%s' "$res" | oneline)\""
    fi
}
# Removes descriptors whose lease OpenBao no longer has (or that are valid again). Called only
# after a pass that logged in and listed leases.
deny_prune() {
    [ -d "$pg_deny_dir" ] || return 0
    for f in "$pg_deny_dir"/*.deny; do
        [ -f "$f" ] || continue
        n="${f##*/}"; n="${n%.deny}"
        grep -qxF "$n" "$state/deny.now" 2>/dev/null && continue
        r="${n%%.*}"; sfx="${n#*.}"
        id="${prefix}$r/$sfx"
        why=''
        if lookup "$id"; then
            case "$l_ttl" in ''|*[!0-9-]*) ;; *) [ "$l_ttl" -gt 0 ] && why="lease valid again (ttl $l_ttl)" ;; esac
        else
            case "$l_err" in *"invalid lease"*) why="lease gone" ;; esac
        fi
        [ -n "$why" ] || continue
        if rm -f "$f"; then log "action=pg-deny-removed lease=$id role=$r outcome=ok detail=\"$why\""; fi
    done
}

revoke() {
    # $1 action, $2 lease id
    res="$(b write sys/leases/revoke lease_id="$2" sync=true 2>&1)"
    if [ $? -eq 0 ]; then
        log "action=$1 lease=$2 role=$(role_of "$2") outcome=ok"
        rm -f "$state/fail.$(key "$2")" "$state/seen.$(key "$2")"
    else
        record_fail "$2"
        log "action=$1 lease=$2 role=$(role_of "$2") outcome=failed detail=\"$(printf '%s' "$res" | oneline)\""
    fi
}

log "action=start interval=${interval}s prefix=$prefix max_backoff_passes=$max_backoff pg_deny_roles=$(echo $pg_deny_roles | tr ' ' ',') pg_deny_dir=$pg_deny_dir"
if [ -n "$(echo $pg_deny_roles)" ] && { [ ! -d "$pg_deny_dir" ] || [ ! -w "$pg_deny_dir" ]; }; then
    log "action=error detail=\"$pg_deny_dir is missing or not writable: no PostgreSQL deny descriptors\""
fi
pass=0
last_err=''
while true; do
    pass=$((pass + 1))
    now="$(date +%s)"
    err=''
    if [ -z "$token" ] || [ $((now - token_at)) -ge "$relogin_after" ]; then
        login || err="login: $login_err"
    fi
    if [ -z "$err" ]; then
        # 1. Irrevocable leases.
        out="$(b read -format=json sys/leases type=irrevocable limit=none 2>&1)"
        if [ $? -ne 0 ]; then
            err="list irrevocable: $(printf '%s' "$out" | oneline)"
            # A token that stopped working (OpenBao restarted, token expired): log in next pass.
            token=''
        fi
    fi
    if [ -n "$err" ]; then
        if [ "$err" != "$last_err" ]; then log "action=error detail=\"$err\""; last_err="$err"; fi
        sleep "$interval"
        continue
    fi
    if [ -n "$last_err" ]; then log "action=recovered"; last_err=''; fi
    if [ ! -f "$state/ready" ]; then : > "$state/ready"; log "action=ready detail=\"logged in to OpenBao, irrevocable-lease listing works\""; fi

    irrevocable="$(printf '%s\n' "$out" | sed -n 's/^ *"lease_id": *"\([^"]*\)".*/\1/p' | grep "^$prefix" || true)"
    : > "$state/deny.now"
    for id in $irrevocable; do
        k="$(key "$id")"
        if [ ! -f "$state/irr.$k" ]; then
            : > "$state/irr.$k"
            log "action=irrevocable-found lease=$id role=$(role_of "$id") outcome=detected"
        fi
        if deny_role "$(role_of "$id")" && lookup "$id"; then deny_write "$id"; fi
        if due "$id"; then revoke revoke-irrevocable "$id"; fi
    done

    # 2. Pending revocations: TTL 0 in two consecutive passes.
    : > "$state/seen.now"
    roles="$(b list -format=json "sys/leases/lookup/$prefix" 2>/dev/null | json_strings)"
    for r in $roles; do
        ids="$(b list -format=json "sys/leases/lookup/$prefix$r" 2>/dev/null | json_strings)"
        for s in $ids; do
            id="$prefix$r$s"
            case " $(echo $irrevocable) " in *" $id "*) continue ;; esac
            lookup "$id" || continue
            ttl="$l_ttl"
            case "$ttl" in ''|*[!0-9-]*) continue ;; esac
            [ "$ttl" -gt 0 ] && continue
            # Deny on the replica from the first pass that sees TTL <= 0 (a revocation OpenBao
            # completes itself is gone within a second and is almost never seen at all).
            deny_write "$id"
            k="$(key "$id")"
            echo "$k" >> "$state/seen.now"
            if [ -f "$state/seen.$k" ]; then
                if due "$id"; then revoke revoke-retried "$id"; fi
            else
                : > "$state/seen.$k"
            fi
        done
    done
    # Forget leases that are gone (revoked by OpenBao itself, or by us).
    for f in "$state"/seen.* "$state"/fail.* "$state"/irr.*; do
        [ -e "$f" ] || continue
        case "$f" in */seen.now) continue ;; esac
        k="${f##*/}"; k="${k#*.}"
        if ! grep -qx "$k" "$state/seen.now" && ! (for id in $irrevocable; do [ "$(key "$id")" = "$k" ] && exit 0; done; exit 1); then
            rm -f "$f"
        fi
    done
    # 3. Descriptors of leases that are gone (revoked by OpenBao or by us above).
    [ -n "$(echo $pg_deny_roles)" ] && deny_prune
    sleep "$interval"
done
