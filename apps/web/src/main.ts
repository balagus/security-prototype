import { bootstrapApplication } from '@angular/platform-browser';
import { provideHttpClient, withFetch } from '@angular/common/http';
import { AppComponent } from './app/app.component';
import { FARO_API_KEY, FARO_ENABLED } from './telemetry-config';

// Start Faro (it patches fetch) before the app makes its first request. With Faro off the
// telemetry chunk is never loaded.
const telemetry: Promise<void> = FARO_ENABLED
  ? import('./telemetry').then((m) => m.initTelemetry(FARO_API_KEY)).catch((err) => console.error('telemetry', err))
  : Promise.resolve();

telemetry
  .then(() =>
    bootstrapApplication(AppComponent, {
      providers: [provideHttpClient(withFetch())],
    }),
  )
  .catch((err) => console.error(err));
