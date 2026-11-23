# Phase 4: postgres:17 plus pgAudit (PostgreSQL License) from the PGDG apt repository that the
# official image already has configured (/etc/apt/sources.list.d/pgdg.list, signed), and tini
# (MIT, Debian package). Used by pg-primary and pg-replica in compose.phase4.yaml; the library is
# only loaded when the server is started with shared_preload_libraries=pgaudit.
# tini is used only by pg-replica, as "tini -s" (child subreaper) above the pg-deny watcher
# (config/postgres/pg-deny-watcher.sh): the postmaster is PID 1, and PostgreSQL 17 treats any
# unknown child that dies by a signal or with an exit code other than 0/1 as a crashed backend
# (measured: "server process (PID n) was terminated by signal 9", every session terminated,
# crash recovery). With tini -s, processes the watcher leaves behind are reaped by tini, never by
# the postmaster. The server itself is not started under tini.
FROM postgres:17

# Exact package versions: the image is rebuilt from scratch in the lab, so pin what was tested.
ARG PGAUDIT_VERSION=17.1-2.pgdg13+2
ARG TINI_VERSION=0.19.0-3+b8

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends "postgresql-17-pgaudit=${PGAUDIT_VERSION}" "tini=${TINI_VERSION}"; \
    rm -rf /var/lib/apt/lists/*; \
    test -f /usr/lib/postgresql/17/lib/pgaudit.so; \
    tini --version
