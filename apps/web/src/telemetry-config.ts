// Browser telemetry switch. This checked-in file keeps Faro OFF.
// The Dockerfile overwrites it at build time from the build args FARO_ENABLED and FARO_API_KEY
// (compose.yaml sets them). The API key is not a secret: it ships in the bundle.
export const FARO_ENABLED = false;
export const FARO_API_KEY = '';
