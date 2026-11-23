using System.Globalization;
using Microsoft.Data.Sqlite;

namespace Portal;

public static class Status
{
    public const string Pending = "pending";     // waiting for an approver
    public const string Active = "active";       // approved, member of the group until expires_at
    public const string Denied = "denied";
    public const string Cancelled = "cancelled"; // withdrawn by the requester before a decision
    public const string Lapsed = "lapsed";       // nobody decided within PendingTimeoutHours
    public const string Expired = "expired";     // ended at expires_at, membership removed
    public const string Revoked = "revoked";     // ended early by an approver or the requester
}

public sealed class AccessRequest
{
    public string Id { get; set; } = "";
    public string App { get; set; } = "";
    public string Group { get; set; } = "";
    public string RequesterSub { get; set; } = "";
    public string Requester { get; set; } = "";
    public string Ticket { get; set; } = "";
    public string Reason { get; set; } = "";
    public int DurationMinutes { get; set; }
    public string Status { get; set; } = "";
    public DateTimeOffset CreatedAt { get; set; }
    public string? DecidedBy { get; set; }
    public DateTimeOffset? DecidedAt { get; set; }
    public string? DecisionComment { get; set; }
    public DateTimeOffset? GrantedAt { get; set; }
    public DateTimeOffset? ExpiresAt { get; set; }
    // Set when an active grant must end before expires_at (revoke). The membership removal then
    // happens in the same pass as an expiry, and is retried until it succeeds.
    public string? EndKind { get; set; }
    public string? EndedBy { get; set; }
    public string? EndReason { get; set; }
    public DateTimeOffset? EndedAt { get; set; }
    public int RemovalAttempts { get; set; }
}

public sealed record RequestEvent(long Id, DateTimeOffset At, string? RequestId, string Actor, string Action, string? Detail);

// SQLite on the portal-data volume. All writes go through AccessService, which serializes them.
public sealed class Store
{
    private readonly string _cs;

    public Store(PortalOptions o)
    {
        Directory.CreateDirectory(o.DataDir);
        _cs = new SqliteConnectionStringBuilder { DataSource = Path.Combine(o.DataDir, "portal.db"), Pooling = true }.ToString();
        using var c = Open();
        Exec(c, """
            PRAGMA journal_mode = WAL;
            CREATE TABLE IF NOT EXISTS requests (
              id TEXT PRIMARY KEY,
              app TEXT NOT NULL,
              grp TEXT NOT NULL,
              requester_sub TEXT NOT NULL,
              requester TEXT NOT NULL,
              ticket TEXT NOT NULL,
              reason TEXT NOT NULL,
              duration_minutes INTEGER NOT NULL,
              status TEXT NOT NULL,
              created_at TEXT NOT NULL,
              decided_by TEXT, decided_at TEXT, decision_comment TEXT,
              granted_at TEXT, expires_at TEXT,
              end_kind TEXT, ended_by TEXT, end_reason TEXT, ended_at TEXT,
              removal_attempts INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS ix_requests_status ON requests(status);
            CREATE TABLE IF NOT EXISTS events (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              at TEXT NOT NULL,
              request_id TEXT,
              actor TEXT NOT NULL,
              action TEXT NOT NULL,
              detail TEXT
            );
            CREATE INDEX IF NOT EXISTS ix_events_request ON events(request_id);
            """);
    }

    private SqliteConnection Open()
    {
        var c = new SqliteConnection(_cs);
        c.Open();
        return c;
    }

    private static void Exec(SqliteConnection c, string sql)
    {
        using var cmd = c.CreateCommand();
        cmd.CommandText = sql;
        cmd.ExecuteNonQuery();
    }

    private static string? Ts(DateTimeOffset? t) => t?.UtcDateTime.ToString("o", CultureInfo.InvariantCulture);
    private static DateTimeOffset? ParseTs(object v) =>
        v is string s ? DateTimeOffset.Parse(s, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal) : null;

    public void Insert(AccessRequest r)
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = """
            INSERT INTO requests (id, app, grp, requester_sub, requester, ticket, reason, duration_minutes, status, created_at)
            VALUES ($id, $app, $grp, $sub, $req, $ticket, $reason, $dur, $status, $created)
            """;
        cmd.Parameters.AddWithValue("$id", r.Id);
        cmd.Parameters.AddWithValue("$app", r.App);
        cmd.Parameters.AddWithValue("$grp", r.Group);
        cmd.Parameters.AddWithValue("$sub", r.RequesterSub);
        cmd.Parameters.AddWithValue("$req", r.Requester);
        cmd.Parameters.AddWithValue("$ticket", r.Ticket);
        cmd.Parameters.AddWithValue("$reason", r.Reason);
        cmd.Parameters.AddWithValue("$dur", r.DurationMinutes);
        cmd.Parameters.AddWithValue("$status", r.Status);
        cmd.Parameters.AddWithValue("$created", Ts(r.CreatedAt));
        cmd.ExecuteNonQuery();
    }

    public void Update(AccessRequest r)
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = """
            UPDATE requests SET status = $status, decided_by = $decidedBy, decided_at = $decidedAt,
              decision_comment = $comment, granted_at = $grantedAt, expires_at = $expiresAt,
              end_kind = $endKind, ended_by = $endedBy, end_reason = $endReason, ended_at = $endedAt,
              removal_attempts = $attempts
            WHERE id = $id
            """;
        cmd.Parameters.AddWithValue("$id", r.Id);
        cmd.Parameters.AddWithValue("$status", r.Status);
        cmd.Parameters.AddWithValue("$decidedBy", (object?)r.DecidedBy ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$decidedAt", (object?)Ts(r.DecidedAt) ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$comment", (object?)r.DecisionComment ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$grantedAt", (object?)Ts(r.GrantedAt) ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$expiresAt", (object?)Ts(r.ExpiresAt) ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$endKind", (object?)r.EndKind ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$endedBy", (object?)r.EndedBy ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$endReason", (object?)r.EndReason ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$endedAt", (object?)Ts(r.EndedAt) ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$attempts", r.RemovalAttempts);
        cmd.ExecuteNonQuery();
    }

    public AccessRequest? Get(string id) => Query("WHERE id = $p0", id).FirstOrDefault();

    public List<AccessRequest> ByStatus(params string[] statuses)
    {
        var names = statuses.Select((_, i) => "$p" + i);
        return Query($"WHERE status IN ({string.Join(",", names)}) ORDER BY created_at", statuses);
    }

    public List<AccessRequest> ByRequester(string sub, int limit = 100) =>
        Query("WHERE requester_sub = $p0 ORDER BY created_at DESC LIMIT " + limit, sub);

    public List<AccessRequest> Recent(int limit = 200) => Query("ORDER BY created_at DESC LIMIT " + limit);

    private List<AccessRequest> Query(string where, params string[] args)
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT id, app, grp, requester_sub, requester, ticket, reason, duration_minutes, status, created_at, " +
                          "decided_by, decided_at, decision_comment, granted_at, expires_at, end_kind, ended_by, end_reason, ended_at, removal_attempts " +
                          "FROM requests " + where;
        for (var i = 0; i < args.Length; i++) cmd.Parameters.AddWithValue("$p" + i, args[i]);
        using var rd = cmd.ExecuteReader();
        var list = new List<AccessRequest>();
        while (rd.Read())
        {
            object V(int i) => rd.IsDBNull(i) ? DBNull.Value : rd.GetValue(i);
            list.Add(new AccessRequest
            {
                Id = rd.GetString(0), App = rd.GetString(1), Group = rd.GetString(2), RequesterSub = rd.GetString(3),
                Requester = rd.GetString(4), Ticket = rd.GetString(5), Reason = rd.GetString(6), DurationMinutes = rd.GetInt32(7),
                Status = rd.GetString(8), CreatedAt = ParseTs(V(9))!.Value,
                DecidedBy = V(10) as string, DecidedAt = ParseTs(V(11)), DecisionComment = V(12) as string,
                GrantedAt = ParseTs(V(13)), ExpiresAt = ParseTs(V(14)),
                EndKind = V(15) as string, EndedBy = V(16) as string, EndReason = V(17) as string, EndedAt = ParseTs(V(18)),
                RemovalAttempts = rd.GetInt32(19),
            });
        }
        return list;
    }

    public void AddEvent(string? requestId, string actor, string action, string? detail)
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "INSERT INTO events (at, request_id, actor, action, detail) VALUES ($at, $rid, $actor, $action, $detail)";
        cmd.Parameters.AddWithValue("$at", Ts(DateTimeOffset.UtcNow));
        cmd.Parameters.AddWithValue("$rid", (object?)requestId ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$actor", actor);
        cmd.Parameters.AddWithValue("$action", action);
        cmd.Parameters.AddWithValue("$detail", (object?)detail ?? DBNull.Value);
        cmd.ExecuteNonQuery();
    }

    public List<RequestEvent> Events(string requestId)
    {
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT id, at, request_id, actor, action, detail FROM events WHERE request_id = $rid ORDER BY id";
        cmd.Parameters.AddWithValue("$rid", requestId);
        using var rd = cmd.ExecuteReader();
        var list = new List<RequestEvent>();
        while (rd.Read())
        {
            list.Add(new RequestEvent(rd.GetInt64(0), ParseTs(rd.GetString(1))!.Value, rd.IsDBNull(2) ? null : rd.GetString(2),
                rd.GetString(3), rd.GetString(4), rd.IsDBNull(5) ? null : rd.GetString(5)));
        }
        return list;
    }
}
