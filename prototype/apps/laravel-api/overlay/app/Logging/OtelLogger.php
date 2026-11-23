<?php

namespace App\Logging;

use Monolog\Level;
use Monolog\Logger;
use OpenTelemetry\API\Globals;
use OpenTelemetry\Contrib\Logs\Monolog\Handler;

/**
 * Phase 5: the "otel" log channel (config/logging.php). Sends Monolog records through the
 * OpenTelemetry logger provider that the SDK autoloader registers (OTEL_PHP_AUTOLOAD_ENABLED),
 * so every line carries the active trace_id/span_id. Without the autoloader the provider is a
 * no-op. Log messages must not contain customer fields: they end up in the debug telemetry.
 */
class OtelLogger
{
    public function __invoke(array $config): Logger
    {
        return new Logger('laravel', [
            new Handler(Globals::loggerProvider(), Level::fromName($config['level'] ?? 'info')),
        ]);
    }
}
