using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;

namespace Portal;

public sealed class KeycloakException(string message) : Exception(message);

public sealed record GroupMember(string Id, string Username);

// Keycloak admin REST API, as the service account of the client "portal-group-manager". Its
// fine-grained admin permissions (setup-portal.ps1) allow exactly: view the managed groups, list
// their members, and add or remove a user to or from them. Anything else returns 403.
public sealed class KeycloakGroups
{
    private readonly HttpClient _http;
    private readonly PortalOptions _o;
    private readonly ILogger<KeycloakGroups> _log;
    private readonly SemaphoreSlim _tokenLock = new(1, 1);
    private readonly ConcurrentDictionary<string, (string Id, DateTimeOffset At)> _groupIds = new();
    private string? _token;
    private DateTimeOffset _tokenExpires;

    public KeycloakGroups(IHttpClientFactory f, PortalOptions o, ILogger<KeycloakGroups> log)
    {
        _http = f.CreateClient("idp");
        _o = o;
        _log = log;
    }

    private async Task<string> Token(CancellationToken ct)
    {
        if (_token is not null && DateTimeOffset.UtcNow < _tokenExpires) return _token;
        await _tokenLock.WaitAsync(ct);
        try
        {
            if (_token is not null && DateTimeOffset.UtcNow < _tokenExpires) return _token;
            using var req = new HttpRequestMessage(HttpMethod.Post, _o.TokenEndpoint)
            {
                Content = new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    ["grant_type"] = "client_credentials",
                    ["client_id"] = _o.GroupManagerClientId,
                    ["client_secret"] = PortalOptions.ReadSecret(_o.GroupManagerSecretFile),
                }),
            };
            using var resp = await _http.SendAsync(req, ct);
            var body = await resp.Content.ReadAsStringAsync(ct);
            if (!resp.IsSuccessStatusCode) throw new KeycloakException($"service account token: HTTP {(int)resp.StatusCode}");
            using var doc = JsonDocument.Parse(body);
            _token = doc.RootElement.GetProperty("access_token").GetString();
            var life = doc.RootElement.TryGetProperty("expires_in", out var e) ? e.GetInt32() : 60;
            _tokenExpires = DateTimeOffset.UtcNow.AddSeconds(Math.Max(10, life - 30));
            return _token!;
        }
        finally { _tokenLock.Release(); }
    }

    private async Task<HttpResponseMessage> Send(HttpMethod m, string relative, CancellationToken ct)
    {
        using var req = new HttpRequestMessage(m, new Uri(_o.AdminBase, relative));
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", await Token(ct));
        return await _http.SendAsync(req, ct);
    }

    // Group IDs are cached for a minute and dropped on any 404: a re-imported realm (Keycloak dev
    // mode) gives the same group a new ID. A stale ID must never turn a removal into a no-op.
    public async Task<string> GroupId(string name, CancellationToken ct, bool fresh = false)
    {
        if (!fresh && _groupIds.TryGetValue(name, out var cached) && cached.At > DateTimeOffset.UtcNow.AddMinutes(-1)) return cached.Id;
        string id;
        using var resp = await Send(HttpMethod.Get, $"groups?search={Uri.EscapeDataString(name)}&exact=true&briefRepresentation=true", ct);
        if (!resp.IsSuccessStatusCode) throw new KeycloakException($"group lookup {name}: HTTP {(int)resp.StatusCode}");
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct));
        foreach (var g in doc.RootElement.EnumerateArray())
        {
            if (g.GetProperty("name").GetString() == name && g.GetProperty("path").GetString() == "/" + name)
            {
                id = g.GetProperty("id").GetString()!;
                _groupIds[name] = (id, DateTimeOffset.UtcNow);
                return id;
            }
        }
        throw new KeycloakException($"group {name} not found (or not visible to {_o.GroupManagerClientId})");
    }

    // Sends a request about a group; on 404 refreshes the group ID once and repeats.
    private async Task<HttpResponseMessage> SendForGroup(HttpMethod m, string group, Func<string, string> path, CancellationToken ct)
    {
        var resp = await Send(m, path(await GroupId(group, ct)), ct);
        if (resp.StatusCode != HttpStatusCode.NotFound) return resp;
        resp.Dispose();
        _groupIds.TryRemove(group, out _);
        return await Send(m, path(await GroupId(group, ct, fresh: true)), ct);
    }

    public async Task<List<GroupMember>> Members(string group, CancellationToken ct)
    {
        var all = new List<GroupMember>();
        for (var first = 0; ; first += 200)
        {
            var f = first;
            using var resp = await SendForGroup(HttpMethod.Get, group, gid => $"groups/{gid}/members?first={f}&max=200&briefRepresentation=true", ct);
            if (!resp.IsSuccessStatusCode) throw new KeycloakException($"members of {group}: HTTP {(int)resp.StatusCode}");
            using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct));
            var n = 0;
            foreach (var u in doc.RootElement.EnumerateArray())
            {
                all.Add(new GroupMember(u.GetProperty("id").GetString()!, u.GetProperty("username").GetString()!));
                n++;
            }
            if (n < 200) return all;
        }
    }

    public async Task AddMember(string userId, string group, CancellationToken ct)
    {
        using var resp = await SendForGroup(HttpMethod.Put, group, gid => $"users/{Uri.EscapeDataString(userId)}/groups/{gid}", ct);
        if (!resp.IsSuccessStatusCode) throw new KeycloakException($"add to {group}: HTTP {(int)resp.StatusCode}");
        _log.LogInformation("added {User} to {Group}", userId, group);
    }

    public async Task RemoveMember(string userId, string group, CancellationToken ct)
    {
        using var resp = await SendForGroup(HttpMethod.Delete, group, gid => $"users/{Uri.EscapeDataString(userId)}/groups/{gid}", ct);
        // 404 with a freshly looked-up group ID: the user no longer exists. Nothing is left to remove.
        if (!resp.IsSuccessStatusCode && resp.StatusCode != HttpStatusCode.NotFound)
            throw new KeycloakException($"remove from {group}: HTTP {(int)resp.StatusCode}");
        _log.LogInformation("removed {User} from {Group}", userId, group);
    }
}
