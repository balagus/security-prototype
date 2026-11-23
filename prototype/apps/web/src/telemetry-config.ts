// Phase 5: browser telemetry switch. This checked-in file keeps Faro OFF (phases 0 to 4).
// The Dockerfile overwrites it at build time from the build args FARO_ENABLED and FARO_API_KEY
// (compose.phase5.yaml sets them). The API key is not a secret: it ships in the bundle.
export const FARO_ENABLED = false;
export const FARO_API_KEY = '';
