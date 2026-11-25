import { Component, DestroyRef, computed, inject, signal } from '@angular/core';
import { HttpClient, HttpErrorResponse, HttpHeaders } from '@angular/common/http';
import { firstValueFrom } from 'rxjs';

interface AppEntry { id: string; name: string; description: string; group: string; approverGroup: string; maxDurationMinutes: number; isApprover: boolean; }

interface Me {
  username: string;
  name: string;
  isApprover: boolean;
  approverGroup: string;
  apps: AppEntry[];
  minDurationMinutes: number;
  maxDurationMinutes: number;
  ticketExample: string;
}

interface AccessRequest {
  id: string;
  app: string;
  group: string;
  requester: string;
  mine: boolean;
  ticket: string;
  reason: string;
  durationMinutes: number;
  status: 'pending' | 'active' | 'denied' | 'cancelled' | 'lapsed' | 'expired' | 'revoked';
  createdAt: string;
  decidedBy: string | null;
  decidedAt: string | null;
  decisionComment: string | null;
  grantedAt: string | null;
  expiresAt: string | null;
  endKind: string | null;
  endedBy: string | null;
  endReason: string | null;
  endedAt: string | null;
  removalPending: boolean;
  actions: string[];
}

interface HistoryEvent { at: string; actor: string; action: string; detail: string | null; }

// State changes need this header (the API refuses POSTs without it: CSRF guard).
const POST_HEADERS = new HttpHeaders({ 'X-Portal-Request': '1' });

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrl: './app.component.css',
})
export class AppComponent {
  private http = inject(HttpClient);

  readonly me = signal<Me | null>(null);
  readonly signedOut = signal(false);
  readonly loadError = signal<string | null>(null);
  readonly mine = signal<AccessRequest[]>([]);
  readonly all = signal<AccessRequest[]>([]);
  readonly now = signal(Date.now());
  readonly busy = signal<string | null>(null);
  readonly toast = signal<{ kind: 'ok' | 'bad'; text: string } | null>(null);
  readonly openHistory = signal<string | null>(null);
  readonly history = signal<HistoryEvent[]>([]);
  readonly comments = signal<Record<string, string>>({});

  // Request form
  readonly fApp = signal('');
  readonly fTicket = signal('');
  readonly fReason = signal('');
  readonly fDuration = signal(60);
  readonly formError = signal<string | null>(null);

  readonly durations = computed(() => {
    const m = this.me();
    if (!m) return [] as number[];
    const opts = new Set<number>();
    if (m.minDurationMinutes < 60) [m.minDurationMinutes, 5, 15, 30].forEach((d) => opts.add(d));
    [60, 120, 180, 240].forEach((d) => opts.add(d));
    const max = this.selectedApp()?.maxDurationMinutes ?? m.maxDurationMinutes;
    return [...opts].filter((d) => d >= m.minDurationMinutes && d <= max).sort((a, b) => a - b);
  });

  readonly selectedApp = computed(() => this.me()?.apps.find((a) => a.id === this.fApp()) ?? null);

  // The write app allows shorter grants than the read app: keep the chosen duration valid.
  clampDuration() {
    const d = this.durations();
    if (d.length && !d.includes(this.fDuration())) this.fDuration.set(d.filter((x) => x <= this.fDuration()).pop() ?? d[0]);
  }

  readonly openForApp = computed(() => this.mine().find((r) => r.app === this.fApp() && (r.status === 'pending' || r.status === 'active')) ?? null);
  readonly pendingForMe = computed(() => this.all().filter((r) => r.status === 'pending' && !r.mine));
  readonly activeGrants = computed(() => this.all().filter((r) => r.status === 'active'));
  readonly recent = computed(() => this.all().filter((r) => r.status !== 'pending' && r.status !== 'active').slice(0, 30));
  readonly myActive = computed(() => this.mine().find((r) => r.status === 'active') ?? null);

  constructor() {
    this.init();
    const tick = setInterval(() => this.now.set(Date.now()), 1000);
    const poll = setInterval(() => { if (this.me()) this.refresh(); }, 10000);
    inject(DestroyRef).onDestroy(() => { clearInterval(tick); clearInterval(poll); });
  }

  private async init() {
    try {
      const me = await firstValueFrom(this.http.get<Me>('/api/me'));
      this.me.set(me);
      if (me.apps.length) this.fApp.set(me.apps[0].id);
      this.fDuration.set(me.minDurationMinutes <= 60 && me.maxDurationMinutes >= 60 ? 60 : me.minDurationMinutes);
      await this.refresh();
    } catch (e) {
      if (e instanceof HttpErrorResponse && e.status === 401) this.signedOut.set(true);
      else this.loadError.set(this.describe(e));
    }
  }

  async refresh() {
    try {
      this.mine.set(await firstValueFrom(this.http.get<AccessRequest[]>('/api/requests')));
      if (this.me()?.isApprover) this.all.set(await firstValueFrom(this.http.get<AccessRequest[]>('/api/requests?scope=all')));
      if (this.openHistory()) await this.loadHistory(this.openHistory()!);
      this.loadError.set(null);
    } catch (e) {
      if (e instanceof HttpErrorResponse && e.status === 401) { this.me.set(null); this.signedOut.set(true); return; }
      this.loadError.set(this.describe(e));
    }
  }

  async submit(ev: Event) {
    ev.preventDefault();
    this.formError.set(null);
    const body = { app: this.fApp(), ticket: this.fTicket().trim(), reason: this.fReason().trim(), durationMinutes: this.fDuration() };
    if (!/^[A-Za-z][A-Za-z0-9]{1,9}-[0-9]{1,7}$/.test(body.ticket)) { this.formError.set('Ticket must look like OPS-1234.'); return; }
    if (body.reason.length < 10) { this.formError.set('Describe why you need access (at least 10 characters).'); return; }
    this.busy.set('create');
    try {
      await firstValueFrom(this.http.post('/api/requests', body, { headers: POST_HEADERS }));
      this.fTicket.set('');
      this.fReason.set('');
      this.flash('ok', 'Request sent. An approver has to confirm it.');
      await this.refresh();
    } catch (e) {
      this.formError.set(this.describe(e));
    } finally {
      this.busy.set(null);
    }
  }

  async act(r: AccessRequest, action: 'approve' | 'deny' | 'cancel' | 'revoke') {
    const comment = (this.comments()[r.id] ?? '').trim();
    if (action === 'deny' && comment.length < 3) { this.flash('bad', 'Add a comment before denying.'); return; }
    if (action === 'revoke' && !confirm(`End ${r.mine ? 'your' : r.requester + "'s"} access to ${r.app} now?`)) return;
    this.busy.set(r.id + action);
    try {
      await firstValueFrom(this.http.post(`/api/requests/${r.id}/${action}`, action === 'cancel' ? {} : { comment }, { headers: POST_HEADERS }));
      const done = { approve: 'Approved. ' + r.requester + ' is now in ' + r.group + '.', deny: 'Denied.', cancel: 'Request withdrawn.', revoke: 'Access ended. Membership removed.' };
      this.flash('ok', done[action]);
      this.comments.update((c) => { const n = { ...c }; delete n[r.id]; return n; });
      await this.refresh();
    } catch (e) {
      this.flash('bad', this.describe(e));
      await this.refresh();
    } finally {
      this.busy.set(null);
    }
  }

  async toggleHistory(id: string) {
    if (this.openHistory() === id) { this.openHistory.set(null); return; }
    this.openHistory.set(id);
    this.history.set([]);
    await this.loadHistory(id);
  }

  private async loadHistory(id: string) {
    try { this.history.set(await firstValueFrom(this.http.get<HistoryEvent[]>(`/api/requests/${id}/history`))); }
    catch { this.history.set([]); }
  }

  setComment(id: string, v: string) { this.comments.update((c) => ({ ...c, [id]: v })); }
  value(ev: Event): string { return (ev.target as HTMLInputElement).value; }

  remaining(r: AccessRequest): string {
    if (!r.expiresAt) return '';
    const s = Math.max(0, Math.floor((Date.parse(r.expiresAt) - this.now()) / 1000));
    if (s === 0) return 'ending';
    const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
    return h ? `${h}h ${m}m left` : m ? `${m}m ${sec}s left` : `${sec}s left`;
  }

  progress(r: AccessRequest): number {
    if (!r.expiresAt || !r.grantedAt) return 0;
    const start = Date.parse(r.grantedAt), end = Date.parse(r.expiresAt);
    return Math.min(100, Math.max(0, ((end - this.now()) / (end - start)) * 100));
  }

  dur(min: number): string { return min % 60 === 0 ? `${min / 60} h` : `${min} min`; }

  when(t: string | null): string {
    if (!t) return '';
    const d = new Date(t);
    const sameDay = d.toDateString() === new Date(this.now()).toDateString();
    return sameDay ? d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
                   : d.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
  }

  ago(t: string | null): string {
    if (!t) return '';
    const s = Math.floor((this.now() - Date.parse(t)) / 1000);
    if (s < 60) return 'just now';
    if (s < 3600) return `${Math.floor(s / 60)} min ago`;
    if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
    return this.when(t);
  }

  outcome(r: AccessRequest): string {
    switch (r.status) {
      case 'pending': return 'Waiting for an approver';
      case 'active': return r.removalPending ? 'Ending: removing membership' : `Approved by ${r.decidedBy}`;
      case 'denied': return `Denied by ${r.decidedBy}`;
      case 'cancelled': return 'Withdrawn';
      case 'lapsed': return 'No decision in time';
      case 'expired': return `Expired ${this.when(r.endedAt)}`;
      case 'revoked': return `Ended early by ${r.endedBy}`;
    }
  }

  private flash(kind: 'ok' | 'bad', text: string) {
    this.toast.set({ kind, text });
    setTimeout(() => { if (this.toast()?.text === text) this.toast.set(null); }, 5000);
  }

  private describe(e: unknown): string {
    if (e instanceof HttpErrorResponse) {
      const msg = typeof e.error === 'object' && e.error?.error ? e.error.error : e.message;
      return e.status ? `${msg} (HTTP ${e.status})` : 'The portal is not reachable.';
    }
    return String(e);
  }
}
