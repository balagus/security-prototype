using System.Text.Json;
using System.Text.Json.Serialization;

namespace Portal;

// One JSON object per line, appended to AuditLogPath on the portal-log volume. Fluent Bit reads
// that volume read-only and ships every line to the audit store (log-store), the same store as
// the OpenBao and database audit records; the portal cannot read or change the store. The same
// events also go to the portal's own database for the request history in the UI.
public sealed class AuditLog
{
    private static readonly JsonSerializerOptions Json = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
    };

    private readonly string _path;
    private readonly Store _store;
    private readonly ILogger<AuditLog> _log;
    private readonly object _lock = new();

    public AuditLog(PortalOptions o, Store store, ILogger<AuditLog> log)
    {
        _path = o.AuditLogPath;
        _store = store;
        _log = log;
        var dir = Path.GetDirectoryName(_path);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
    }

    public sealed record Entry
    {
        public required string Action { get; init; }
        public required string Actor { get; init; }
        public string Outcome { get; init; } = "ok";
        public string? RequestId { get; init; }
        public string? Requester { get; init; }
        public string? App { get; init; }
        public string? Group { get; init; }
        public string? Ticket { get; init; }
        public int? DurationMinutes { get; init; }
        public DateTimeOffset? ExpiresAt { get; init; }
        public string? ClientIp { get; init; }
        public string? Detail { get; init; }
    }

    public void Write(Entry e)
    {
        var line = JsonSerializer.Serialize(new
        {
            time = DateTimeOffset.UtcNow.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"),
            source = "portal",
            action = e.Action,
            outcome = e.Outcome,
            actor = e.Actor,
            request_id = e.RequestId,
            requester = e.Requester,
            app = e.App,
            group = e.Group,
            ticket = e.Ticket,
            duration_minutes = e.DurationMinutes,
            expires_at = e.ExpiresAt?.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            client_ip = e.ClientIp,
            detail = e.Detail,
        }, Json);

        lock (_lock)
        {
            // Open per write: survives log rotation and never keeps a handle on a deleted file.
            // 0640: the shipper reads it through group 4000 (setgid directory); nobody else.
            using var fs = new FileStream(_path, new FileStreamOptions
            {
                Mode = FileMode.Append, Access = FileAccess.Write, Share = FileShare.ReadWrite,
                UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead,
            });
            using var sw = new StreamWriter(fs);
            sw.WriteLine(line);
        }
        _log.LogInformation("audit {Line}", line);

        try { _store.AddEvent(e.RequestId, e.Actor, e.Action, e.Detail is null ? e.Outcome : $"{e.Outcome}: {e.Detail}"); }
        catch (Exception ex) { _log.LogError(ex, "could not store event {Action}", e.Action); }
    }
}
