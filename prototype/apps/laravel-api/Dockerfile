# syntax=docker/dockerfile:1

# ---- build stage: create the Laravel 13 skeleton and apply the overlay ----
FROM composer:2.8 AS build
WORKDIR /app

# --no-scripts: skips the skeleton's post-create hooks (.env copy, key:generate,
# sqlite creation + migrate), so nothing environment-specific is baked in.
RUN composer create-project laravel/laravel:^13.0 /app \
      --no-scripts --no-interaction --prefer-dist --no-dev \
 && rm -f /app/.env /app/.env.example \
 && rm -rf /app/tests /app/database/migrations/* /app/database/*.sqlite

COPY overlay/ /app/

# Writes bootstrap/cache/packages.php + services.php (no secrets, no config cache).
RUN php artisan package:discover --ansi \
 && rm -f /app/.env

# ---- runtime stage ----
FROM php:8.4-fpm

RUN docker-php-ext-install pdo_mysql

COPY --from=build --chown=www-data:www-data /app /var/www/html
COPY docker/zzz-app.conf /usr/local/etc/php-fpm.d/zzz-app.conf
COPY entrypoint.sh /usr/local/bin/entrypoint.sh

RUN sed -i 's/\r$//' /usr/local/bin/entrypoint.sh /usr/local/etc/php-fpm.d/zzz-app.conf \
 && chmod +x /usr/local/bin/entrypoint.sh \
 && rm -f /var/www/html/.env \
 && mkdir -p /var/www/html/storage/framework/cache/data /var/www/html/storage/framework/sessions \
             /var/www/html/storage/framework/views /var/www/html/storage/logs \
 && chown -R www-data:www-data /var/www/html/storage /var/www/html/bootstrap/cache \
 && chmod -R ug+rwX /var/www/html/storage /var/www/html/bootstrap/cache

# Defaults only; compose overrides. No secrets here.
ENV DB_CONNECTION=mariadb \
    SESSION_DRIVER=array \
    CACHE_STORE=array \
    LOG_CHANNEL=stderr \
    QUEUE_CONNECTION=sync

WORKDIR /var/www/html
EXPOSE 9000
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["php-fpm"]
