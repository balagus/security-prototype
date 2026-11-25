using System.Text.RegularExpressions;

namespace Portal;

// Groups: the caller's Keycloak groups (token claim "groups", without a leading "/").
public sealed record Caller(string Sub, string Username, string DisplayName, IReadOnlySet<string> Groups, string? Ip);

public sealed record Outcome(int Status, object Body)
{
    public static Outcome Error(int status, string message) => new(status, new { error = message });
}

public sealed record CreateBody(string? App, string? Ticket, string? Reason, int? DurationMinutes);
public sealed record DecisionBody(string? Comment);

// The approval rules (docs/DECISIONS.md D11):
//   1. a developer requests access: app, ticket ID, reason, duration
//   2. a different person in the approver group approves (or denies); the portal records both
//   3. the portal adds the requester to the app's Keycloak group (app1-devs)
//   4. at expiry, or when revoked, the portal removes the membership again
//   5. the developer logs in to OpenBao personally; the portal never touches OpenBao or a database
// Every state change is serialized by one lock (one portal instance) and written to the audit log.
public sealed class AccessService
{
    private readonly Store _store;
    private readonly KeycloakGroups _kc;
    private readonly AuditLog _audit;
    private readonly PortalOptions _o;
    private readonly ILogger<AccessService> _log;
    private readonly SemaphoreSlim _lock = new(1, 1);
    private readonly Regex _ticket;
    // Drift already reported (group|user id), so a member that stays is reported once, not every pass.
    private readonly HashSet<string> _reported = new();

    public AccessService(Store store, KeycloakGroups kc, AuditLog audit, PortalOptions o, ILogger<AccessService> log)
    {
        _store = store; _kc = kc; _audit = audit; _o = o; _log = log;
        _ticket = new Regex(o.TicketPattern, RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
    }

    private bool IsStanding(string group, string username) =>
        _o.Apps.Where(a => a.Group == group).Any(a => a.StandingMembers.Contains(username, StringComparer.OrdinalIgnoreCase));

    // Approver rights are per app (the write app has its own approver group).
    private string ApproverGroupOf(string appId) => _o.App(appId) is AppEntry a ? _o.ApproverGroupOf(a) : _o.ApproverGroup;
    private bool Approves(Caller c, string appId) => c.Groups.Contains(ApproverGroupOf(appId));
    public bool ApprovesAny(Caller c) => _o.Apps.Any(a => Approves(c, a.Id));

    private static bool IsDue(AccessRequest r, DateTimeOffset now) =>
        r.Status == Status.Active && (r.EndKind is not null || r.ExpiresAt <= now);

    private AuditLog.Entry Entry(string action, Caller? c, AccessRequest? r, string outcome = "ok", string? detail = null) => new()
    {
        Action = action,
        Actor = c?.Username ?? "portal",
        Outcome = outcome,
        RequestId = r?.Id,
        Requester = r?.Requester,
        App = r?.App,
        Group = r?.Group,
        Ticket = r?.Ticket,
        DurationMinutes = r?.DurationMinutes,
        ExpiresAt = r?.Status == Status.Active ? r.ExpiresAt : null,
        ClientIp = c?.Ip,
        Detail = detail,
    };

    // ---- requests ---------------------------------------------------------------------------

    public async Task<Outcome> Create(Caller c, CreateBody b, CancellationToken ct)
    {
        var app = _o.App(b.App);
        if (app is null) return Outcome.Error(400, "unknown app");
        var maxDur = _o.MaxDurationOf(app);
        var ticket = (b.Ticket ?? "").Trim().ToUpperInvariant();
        if (!_ticket.IsMatch(ticket)) return Outcome.Error(400, "ticket must look like ABC-123");
        var reason = (b.Reason ?? "").Trim();
        if (reason.Length < 10 || reason.Length > 500) return Outcome.Error(400, "reason must be 10 to 500 characters");
        if (b.DurationMinutes is not int dur || dur < _o.MinDurationMinutes || dur > maxDur)
            return Outcome.Error(400, $"duration must be {_o.MinDurationMinutes} to {maxDur} minutes");

        var r = new AccessRequest
        {
            Id = Guid.NewGuid().ToString("n")[..12],
            App = app.Id, Group = app.Group, RequesterSub = c.Sub, Requester = c.Username,
            Ticket = ticket, Reason = reason, DurationMinutes = dur,
            Status = Status.Pending, CreatedAt = DateTimeOffset.UtcNow,
        };

        if (IsStanding(app.Group, c.Username))
        {
            _audit.Write(Entry("request-refused", c, r, "refused", "requester has standing access"));
            return Outcome.Error(409, $"you already have standing access to {app.Id}");
        }

        await _lock.WaitAsync(ct);
        try
        {
            if (_store.ByRequester(c.Sub).Any(x => x.App == app.Id && x.Status is Status.Pending or Status.Active))
                return Outcome.Error(409, $"you already have an open request or an active grant for {app.Id}");

            List<GroupMember> members;
            try { members = await _kc.Members(app.Group, ct); }
            catch (Exception ex) when (ex is KeycloakException or HttpRequestException or TaskCanceledException)
            {
                _audit.Write(Entry("request-refused", c, r, "error", "identity provider unavailable: " + ex.Message));
                return Outcome.Error(502, "the identity provider is unavailable, try again");
            }
            if (members.Any(m => m.Id == c.Sub))
            {
                _audit.Write(Entry("request-refused", c, r, "refused", $"requester is already a member of {app.Group} outside the portal"));
                return Outcome.Error(409, $"you are already a member of {app.Group} outside the portal; ask an administrator");
            }

            _store.Insert(r);
            _audit.Write(Entry("request-created", c, r, detail: reason));
            return new Outcome(201, ToDto(r, c));
        }
        finally { _lock.Release(); }
    }

    public async Task<Outcome> Approve(string id, Caller c, DecisionBody b, CancellationToken ct)
    {
        await _lock.WaitAsync(ct);
        try
        {
            var r = _store.Get(id);
            if (r is null) return Outcome.Error(404, "no such request");
            if (!Approves(c, r.App))
            {
                _audit.Write(Entry("approval-refused", c, r, "refused", "caller is not in " + ApproverGroupOf(r.App)));
                return Outcome.Error(403, "only members of " + ApproverGroupOf(r.App) + " can approve");
            }
            if (r.RequesterSub == c.Sub)
            {
                _audit.Write(Entry("self-approval-refused", c, r, "refused", "approver and requester are the same person"));
                return Outcome.Error(403, "you cannot approve your own request");
            }
            if (r.Status != Status.Pending) return Outcome.Error(409, $"request is {r.Status}");
            var comment = Clip(b.Comment);

            try { await _kc.AddMember(r.RequesterSub, r.Group, ct); }
            catch (Exception ex) when (ex is KeycloakException or HttpRequestException or TaskCanceledException)
            {
                _audit.Write(Entry("membership-add-failed", c, r, "error", ex.Message));
                return Outcome.Error(502, "could not add the membership in Keycloak; the request is still pending");
            }

            var now = DateTimeOffset.UtcNow;
            r.Status = Status.Active;
            r.DecidedBy = c.Username; r.DecidedAt = now; r.DecisionComment = comment;
            r.GrantedAt = now; r.ExpiresAt = now.AddMinutes(r.DurationMinutes);
            _store.Update(r);
            _audit.Write(Entry("request-approved", c, r, detail: comment));
            _audit.Write(Entry("membership-added", null, r, detail: $"{r.Requester} added to {r.Group} until {r.ExpiresAt:yyyy-MM-ddTHH:mm:ssZ}"));
            return new Outcome(200, ToDto(r, c));
        }
        finally { _lock.Release(); }
    }

    public async Task<Outcome> Deny(string id, Caller c, DecisionBody b, CancellationToken ct)
    {
        await _lock.WaitAsync(ct);
        try
        {
            var r = _store.Get(id);
            if (r is null) return Outcome.Error(404, "no such request");
            if (!Approves(c, r.App))
            {
                _audit.Write(Entry("approval-refused", c, r, "refused", "caller is not in " + ApproverGroupOf(r.App)));
                return Outcome.Error(403, "only members of " + ApproverGroupOf(r.App) + " can deny");
            }
            if (r.Status != Status.Pending) return Outcome.Error(409, $"request is {r.Status}");
            var comment = Clip(b.Comment);
            if (comment is null || comment.Length < 3) return Outcome.Error(400, "a denial needs a comment");
            r.Status = Status.Denied; r.DecidedBy = c.Username; r.DecidedAt = DateTimeOffset.UtcNow; r.DecisionComment = comment;
            _store.Update(r);
            _audit.Write(Entry("request-denied", c, r, detail: comment));
            return new Outcome(200, ToDto(r, c));
        }
        finally { _lock.Release(); }
    }

    public async Task<Outcome> Cancel(string id, Caller c, CancellationToken ct)
    {
        await _lock.WaitAsync(ct);
        try
        {
            var r = _store.Get(id);
            if (r is null || r.RequesterSub != c.Sub) return Outcome.Error(404, "no such request");
            if (r.Status != Status.Pending) return Outcome.Error(409, $"request is {r.Status}");
            r.Status = Status.Cancelled; r.EndedBy = c.Username; r.EndedAt = DateTimeOffset.UtcNow;
            _store.Update(r);
            _audit.Write(Entry("request-cancelled", c, r));
            return new Outcome(200, ToDto(r, c));
        }
        finally { _lock.Release(); }
    }

    // Ends an active grant now. The requester may end their own; approvers may end anyone's.
    public async Task<Outcome> Revoke(string id, Caller c, DecisionBody b, CancellationToken ct)
    {
        await _lock.WaitAsync(ct);
        try
        {
            var r = _store.Get(id);
            if (r is null || (r.RequesterSub != c.Sub && !Approves(c, r.App))) return Outcome.Error(404, "no such request");
            if (r.Status != Status.Active) return Outcome.Error(409, $"request is {r.Status}");
            if (r.EndKind is null)
            {
                r.EndKind = Status.Revoked; r.EndedBy = c.Username; r.EndReason = Clip(b.Comment);
                _store.Update(r);
                _audit.Write(Entry("revoke-requested", c, r, detail: r.EndReason));
            }
            var removed = await EndGrant(r, ct);
            return removed ? new Outcome(200, ToDto(r, c))
                           : Outcome.Error(502, "could not remove the membership in Keycloak; it is retried automatically");
        }
        finally { _lock.Release(); }
    }

    // Removes the membership of a due grant. Caller holds the lock. False: Keycloak failed, the
    // grant stays active (and due) and the next pass retries.
    private async Task<bool> EndGrant(AccessRequest r, CancellationToken ct)
    {
        try { await _kc.RemoveMember(r.RequesterSub, r.Group, ct); }
        catch (Exception ex) when (ex is KeycloakException or HttpRequestException or TaskCanceledException)
        {
            r.RemovalAttempts++;
            _store.Update(r);
            _audit.Write(Entry("membership-remove-failed", null, r, "error", $"attempt {r.RemovalAttempts}: {ex.Message}"));
            return false;
        }
        var kind = r.EndKind ?? Status.Expired;
        r.Status = kind;
        r.EndedAt = DateTimeOffset.UtcNow;
        r.EndedBy ??= "portal";
        _store.Update(r);
        _audit.Write(Entry("membership-removed", null, r, detail: $"{r.Requester} removed from {r.Group}"));
        _audit.Write(Entry(kind == Status.Revoked ? "access-revoked" : "access-expired", null, r,
            detail: kind == Status.Revoked ? $"ended early by {r.EndedBy}" : "reached expires_at"));
        return true;
    }

    // ---- background pass (ExpiryWorker) -------------------------------------------------------

    public async Task Reconcile(CancellationToken ct)
    {
        await _lock.WaitAsync(ct);
        try
        {
            var now = DateTimeOffset.UtcNow;
            foreach (var r in _store.ByStatus(Status.Pending).Where(r => r.CreatedAt.AddHours(_o.PendingTimeoutHours) <= now))
            {
                r.Status = Status.Lapsed; r.EndedAt = now; r.EndedBy = "portal";
                _store.Update(r);
                _audit.Write(Entry("request-lapsed", null, r, detail: $"no decision within {_o.PendingTimeoutHours} h"));
            }

            var active = _store.ByStatus(Status.Active);
            foreach (var r in active.Where(r => IsDue(r, now))) await EndGrant(r, ct);

            // Drift: every member of a managed group must be a standing member or hold an active grant.
            foreach (var group in _o.Apps.Select(a => a.Group).Distinct())
            {
                List<GroupMember> members;
                try { members = await _kc.Members(group, ct); }
                catch (Exception ex) when (ex is KeycloakException or HttpRequestException or TaskCanceledException)
                {
                    _log.LogWarning("drift check of {Group} skipped: {Error}", group, ex.Message);
                    continue;
                }
                var granted = _store.ByStatus(Status.Active).Where(r => r.Group == group && !IsDue(r, now)).ToList();
                var grantedSubs = granted.Select(r => r.RequesterSub).ToHashSet();
                var seen = new HashSet<string>();
                foreach (var m in members)
                {
                    var key = group + "|" + m.Id;
                    seen.Add(key);
                    if (IsStanding(group, m.Username) || grantedSubs.Contains(m.Id)) { _reported.Remove(key); continue; }
                    var remove = string.Equals(_o.DriftAction, "remove", StringComparison.OrdinalIgnoreCase);
                    if (!_reported.Contains(key) || remove)
                    {
                        _audit.Write(new AuditLog.Entry
                        {
                            Action = "membership-drift", Actor = "portal", Outcome = "alert", Requester = m.Username, Group = group,
                            Detail = $"{m.Username} is a member of {group} without an approved, active grant (added outside the portal)",
                        });
                        _reported.Add(key);
                    }
                    if (!remove) continue;
                    try
                    {
                        await _kc.RemoveMember(m.Id, group, ct);
                        _audit.Write(new AuditLog.Entry
                        {
                            Action = "drift-removed", Actor = "portal", Requester = m.Username, Group = group,
                            Detail = $"{m.Username} removed from {group}",
                        });
                        _reported.Remove(key);
                    }
                    catch (Exception ex) when (ex is KeycloakException or HttpRequestException or TaskCanceledException)
                    {
                        _audit.Write(new AuditLog.Entry
                        {
                            Action = "membership-remove-failed", Actor = "portal", Outcome = "error", Requester = m.Username, Group = group,
                            Detail = "drift removal: " + ex.Message,
                        });
                    }
                }
                _reported.RemoveWhere(k => k.StartsWith(group + "|", StringComparison.Ordinal) && !seen.Contains(k));

                // The opposite drift: an active grant whose membership was removed by someone else.
                var memberIds = members.Select(m => m.Id).ToHashSet();
                foreach (var r in granted.Where(r => !memberIds.Contains(r.RequesterSub)))
                {
                    var key = "missing|" + r.Id;
                    if (_reported.Add(key))
                        _audit.Write(Entry("grant-membership-missing", null, r, "alert", $"{r.Requester} is no longer in {r.Group}, removed outside the portal"));
                }
            }
        }
        finally { _lock.Release(); }
    }

    // ---- views ------------------------------------------------------------------------------

    public object Mine(Caller c) => _store.ByRequester(c.Sub).Select(r => ToDto(r, c)).ToList();

    // Approvers see the requests of the apps they decide.
    public object All(Caller c) => _store.Recent().Where(r => Approves(c, r.App)).Select(r => ToDto(r, c)).ToList();

    public Outcome History(string id, Caller c)
    {
        var r = _store.Get(id);
        if (r is null || (r.RequesterSub != c.Sub && !Approves(c, r.App))) return Outcome.Error(404, "no such request");
        return new Outcome(200, _store.Events(id).Select(e => new { at = e.At, actor = e.Actor, action = e.Action, detail = e.Detail }));
    }

    public object ToDto(AccessRequest r, Caller c)
    {
        var now = DateTimeOffset.UtcNow;
        var mine = r.RequesterSub == c.Sub;
        var actions = new List<string>();
        if (r.Status == Status.Pending && mine) actions.Add("cancel");
        var approver = Approves(c, r.App);
        if (r.Status == Status.Pending && approver && !mine) { actions.Add("approve"); actions.Add("deny"); }
        if (r.Status == Status.Active && r.EndKind is null && (mine || approver)) actions.Add("revoke");
        return new
        {
            id = r.Id, app = r.App, group = r.Group, requester = r.Requester, mine,
            ticket = r.Ticket, reason = r.Reason, durationMinutes = r.DurationMinutes,
            status = r.Status, createdAt = r.CreatedAt,
            decidedBy = r.DecidedBy, decidedAt = r.DecidedAt, decisionComment = r.DecisionComment,
            grantedAt = r.GrantedAt, expiresAt = r.ExpiresAt,
            endKind = r.EndKind, endedBy = r.EndedBy, endReason = r.EndReason, endedAt = r.EndedAt,
            removalPending = r.Status == Status.Active && IsDue(r, now),
            actions,
        };
    }

    private static string? Clip(string? s)
    {
        s = s?.Trim();
        if (string.IsNullOrEmpty(s)) return null;
        return s.Length > 500 ? s[..500] : s;
    }
}

public sealed class ExpiryWorker(AccessService svc, PortalOptions o, ILogger<ExpiryWorker> log) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        // First pass right away: grants that expired while the portal was down end now.
        while (!ct.IsCancellationRequested)
        {
            try { await svc.Reconcile(ct); }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
            catch (Exception ex) { log.LogError(ex, "reconcile pass failed"); }
            try { await Task.Delay(TimeSpan.FromSeconds(Math.Max(5, o.ReconcileSeconds)), ct); }
            catch (OperationCanceledException) { break; }
        }
    }
}
