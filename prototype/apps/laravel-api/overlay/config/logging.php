<?php

/*
 * Phase 5: adds the "otel" channel (app/Logging/OtelLogger.php). Laravel merges the "channels"
 * of this file with the framework's default logging configuration, so stderr, stack, ... stay
 * as they are. LOG_CHANNEL selects the channel: stderr in phases 0 to 4, otel in phase 5.
 * Adapted from balagus/telemetries examples/laravel/config/logging.otel.php.
 */

return [
    'channels' => [
        'otel' => [
            'driver' => 'custom',
            'via' => App\Logging\OtelLogger::class,
            'level' => env('LOG_LEVEL', 'info'),
        ],
    ],
];
