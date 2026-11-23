/**
 * Phase 5: browser telemetry with Grafana Faro (Apache-2.0): errors, web vitals, sessions and
 * traces. Adapted from balagus/telemetries examples/react/src/telemetry.ts.
 *
 * Loaded only when FARO_ENABLED (telemetry-config.ts) is true. Sends to /faro/collect on the
 * same origin; nginx proxies that to Alloy, which masks e-mail addresses before storing.
 * - Tracing patches fetch (Angular uses provideHttpClient(withFetch())), so a click becomes one
 *   trace: browser span -> traceparent on /dotnet/ and /laravel/ -> API -> SQL.
 * - No cross-origin header propagation; no user identity; console capture limited to errors.
 */
import { getWebInstrumentations, initializeFaro, LogLevel } from '@grafana/faro-web-sdk';
import { TracingInstrumentation } from '@grafana/faro-web-tracing';

export function initTelemetry(apiKey: string): void {
  initializeFaro({
    url: '/faro/collect',
    apiKey,
    app: { name: 'web', version: '1.0.0', environment: 'lab' },
    consoleInstrumentation: {
      disabledLevels: [LogLevel.TRACE, LogLevel.DEBUG, LogLevel.LOG, LogLevel.INFO, LogLevel.WARN],
    },
    instrumentations: [
      ...getWebInstrumentations({ captureConsole: true }),
      new TracingInstrumentation({
        instrumentationOptions: {
          // Same-origin requests (/dotnet/, /laravel/) always get traceparent; nothing else.
          propagateTraceHeaderCorsUrls: [],
        },
      }),
    ],
    ignoreErrors: [/ResizeObserver loop/, /Script error\./],
    sessionTracking: { enabled: true, samplingRate: 1 },
  });
}
