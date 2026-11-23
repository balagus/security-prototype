import { Component, inject, signal } from '@angular/core';
import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { firstValueFrom } from 'rxjs';

interface Customer {
  id: number | string;
  email: string;
  full_name: string;
  created_at: string;
}

interface Order {
  id: number | string;
  customer_id: number | string;
  total: number | string;
  created_at: string;
}

interface Section {
  title: string;
  prefix: string;
  health: ReturnType<typeof signal<string>>;
  customers: ReturnType<typeof signal<Customer[]>>;
  orders: ReturnType<typeof signal<Order[]>>;
  errors: ReturnType<typeof signal<string[]>>;
  email: ReturnType<typeof signal<string>>;
  fullName: ReturnType<typeof signal<string>>;
  busy: ReturnType<typeof signal<boolean>>;
}

function makeSection(title: string, prefix: string): Section {
  return {
    title,
    prefix,
    health: signal('checking...'),
    customers: signal<Customer[]>([]),
    orders: signal<Order[]>([]),
    errors: signal<string[]>([]),
    email: signal(''),
    fullName: signal(''),
    busy: signal(false),
  };
}

@Component({
  selector: 'app-root',
  template: `
    <h1>Security prototype</h1>
    @for (s of sections; track s.prefix) {
      <section>
        <h2>{{ s.title }}</h2>
        <p>Health: <strong>{{ s.health() }}</strong></p>

        @for (e of s.errors(); track $index) {
          <p class="error">{{ e }}</p>
        }

        <h3>Customers</h3>
        <table>
          <thead><tr><th>id</th><th>email</th><th>full_name</th><th>created_at</th></tr></thead>
          <tbody>
            @for (c of s.customers(); track c.id) {
              <tr><td>{{ c.id }}</td><td>{{ c.email }}</td><td>{{ c.full_name }}</td><td>{{ c.created_at }}</td></tr>
            } @empty {
              <tr><td colspan="4">none</td></tr>
            }
          </tbody>
        </table>

        <form (submit)="addCustomer(s, $event)">
          <input type="email" name="email" placeholder="email" required
                 [value]="s.email()" (input)="s.email.set($any($event.target).value)">
          <input type="text" name="full_name" placeholder="full name" required
                 [value]="s.fullName()" (input)="s.fullName.set($any($event.target).value)">
          <button type="submit" [disabled]="s.busy()">Add customer</button>
        </form>

        <h3>Orders</h3>
        <table>
          <thead><tr><th>id</th><th>customer_id</th><th>total</th><th>created_at</th></tr></thead>
          <tbody>
            @for (o of s.orders(); track o.id) {
              <tr><td>{{ o.id }}</td><td>{{ o.customer_id }}</td><td>{{ o.total }}</td><td>{{ o.created_at }}</td></tr>
            } @empty {
              <tr><td colspan="4">none</td></tr>
            }
          </tbody>
        </table>
      </section>
    }
  `,
  styles: `
    :host { display: block; font-family: sans-serif; margin: 1rem; }
    section { border: 1px solid #999; padding: 0.5rem 1rem; margin-bottom: 1rem; }
    table { border-collapse: collapse; margin-bottom: 0.5rem; }
    th, td { border: 1px solid #ccc; padding: 2px 8px; text-align: left; }
    form { margin: 0.5rem 0; }
    input { margin-right: 0.5rem; }
    .error { color: #b00020; font-weight: bold; }
  `,
})
export class AppComponent {
  private readonly http = inject(HttpClient);

  readonly sections: Section[] = [
    makeSection('.NET API (PostgreSQL)', '/dotnet'),
    makeSection('Laravel API (MariaDB)', '/laravel'),
  ];

  constructor() {
    for (const s of this.sections) {
      void this.refresh(s);
    }
  }

  private describe(what: string, err: unknown): string {
    if (err instanceof HttpErrorResponse) {
      return `${what} failed: HTTP ${err.status} ${err.statusText}`.trim();
    }
    return `${what} failed: ${err instanceof Error ? err.message : String(err)}`;
  }

  private rows<T>(body: unknown): T[] {
    if (Array.isArray(body)) {
      return body as T[];
    }
    const data = (body as { data?: unknown } | null)?.data;
    return Array.isArray(data) ? (data as T[]) : [];
  }

  async refresh(s: Section): Promise<void> {
    s.errors.set([]);
    const fail = (what: string, err: unknown) =>
      s.errors.update((list) => [...list, this.describe(what, err)]);

    const health = firstValueFrom(
      this.http.get(`${s.prefix}/health`, { responseType: 'text' }),
    ).then(
      (t) => s.health.set(t.trim().slice(0, 200) || 'ok'),
      (e) => {
        s.health.set('DOWN');
        fail('GET /health', e);
      },
    );
    const orders = firstValueFrom(this.http.get<unknown>(`${s.prefix}/api/orders`)).then(
      (b) => s.orders.set(this.rows<Order>(b)),
      (e) => fail('GET /api/orders', e),
    );
    await Promise.all([health, this.loadCustomers(s), orders]);
  }

  private async loadCustomers(s: Section): Promise<void> {
    try {
      const body = await firstValueFrom(this.http.get<unknown>(`${s.prefix}/api/customers`));
      s.customers.set(this.rows<Customer>(body));
    } catch (e) {
      s.errors.update((list) => [...list, this.describe('GET /api/customers', e)]);
    }
  }

  async addCustomer(s: Section, event: Event): Promise<void> {
    event.preventDefault();
    s.busy.set(true);
    try {
      await firstValueFrom(
        this.http.post(`${s.prefix}/api/customers`, {
          email: s.email(),
          full_name: s.fullName(),
        }),
      );
      s.email.set('');
      s.fullName.set('');
      s.errors.set([]);
    } catch (e) {
      s.errors.update((list) => [...list, this.describe('POST /api/customers', e)]);
      s.busy.set(false);
      return;
    }
    s.busy.set(false);
    await this.loadCustomers(s);
  }
}