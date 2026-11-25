#!/bin/sh
set -e

# Export NAME from NAME_FILE (Docker secrets). $(...) strips trailing newlines.
load_file_var() {
    name="$1"
    eval "file=\${${name}_FILE:-}"
    if [ -n "$file" ]; then
        if [ ! -r "$file" ]; then
            echo "entrypoint: ${name}_FILE=$file is not readable" >&2
            exit 1
        fi
        val="$(cat "$file")"
        export "$name=$val"
    fi
}

for v in APP_KEY DB_PASSWORD DB_USERNAME MIGRATOR_DB_USERNAME MIGRATOR_DB_PASSWORD; do
    load_file_var "$v"
done

wait_for_db() {
    i=0
    while [ "$i" -lt 30 ]; do
        # With MYSQL_ATTR_SSL_CA set, connect over TLS with that CA, the same
        # option config/database.php passes, so a server requiring TLS accepts the probe.
        if php -r '
            $opts = [PDO::ATTR_TIMEOUT => 3];
            $ca = getenv("MYSQL_ATTR_SSL_CA");
            if ($ca !== false && $ca !== "") {
                $opts[class_exists("Pdo\\Mysql") ? Pdo\Mysql::ATTR_SSL_CA : PDO::MYSQL_ATTR_SSL_CA] = $ca;
            }
            try {
                new PDO(
                    "mysql:host=" . getenv("DB_HOST") . ";port=" . (getenv("DB_PORT") ?: "3306") . ";dbname=" . getenv("DB_DATABASE"),
                    getenv("DB_USERNAME"),
                    getenv("DB_PASSWORD"),
                    $opts
                );
                exit(0);
            } catch (Throwable $e) {
                fwrite(STDERR, "entrypoint: db probe: " . $e->getMessage() . "\n");
                exit(1);
            }
        ' >/dev/null; then
            return 0
        fi
        i=$((i + 1))
        echo "entrypoint: waiting for database ($i/30)..." >&2
        sleep 2
    done
    echo "entrypoint: database not reachable after ~60s" >&2
    return 1
}

if [ "${1:-}" = "migrate" ]; then
    if [ -n "${MIGRATOR_DB_USERNAME:-}" ]; then DB_USERNAME="$MIGRATOR_DB_USERNAME"; export DB_USERNAME; fi
    if [ -n "${MIGRATOR_DB_PASSWORD:-}" ]; then DB_PASSWORD="$MIGRATOR_DB_PASSWORD"; export DB_PASSWORD; fi
    wait_for_db || exit 1
    exec php artisan migrate --force
fi

if [ "${RUN_MIGRATIONS_ON_STARTUP:-}" = "true" ]; then
    wait_for_db || exit 1
    php artisan migrate --force
fi

exec "$@"
