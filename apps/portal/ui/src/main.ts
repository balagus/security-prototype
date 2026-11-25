import { bootstrapApplication } from '@angular/platform-browser';
import { provideHttpClient, withFetch } from '@angular/common/http';
import { AppComponent } from './app/app.component';

// Zoneless (the Angular default): all view state is in signals.
bootstrapApplication(AppComponent, {
  providers: [provideHttpClient(withFetch())],
}).catch((err) => console.error(err));
