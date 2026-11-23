namespace Portal;

// Configuration section "Portal" (appsettings.json, overridden by Portal__* environment
// variables in compose.phase6.yaml). Secrets are read from files, never from the environment.
public sealed class PortalOptions
{
    // OIDC issuer of the Keycloak realm, exactly as it appears in tokens.
    public string Authority { get; set; } = "";

    // Back-channel only: connect to this host instead of the authority's host (same port). The
    // issuer is keycloak.localhost, which browsers resolve to loopback; inside Docker the
    // container is reached by its service name. Empty = use the authority's host.
    public string IdpConnectHost { get; set; } = "";

    // Interactive sign-in (confidential client, code flow with PKCE).
    public string ClientId { get; set; } = "portal";
    public string ClientSecretFile { get; set; } = "/run/secrets/portal_oidc_client_secret";

    // Group management (service account, client credentials). In Keycloak it may only change
    // the membership of the managed groups (fine-grained admin permissions, phase6-setup.ps1).
    public string GroupManagerClientId { get; set; } = "portal-group-manager";
    public string GroupManagerSecretFile { get; set; } = "/run/secrets/portal_group_manager_secret";

    // Members of this Keycloak group may approve, deny and revoke. Never their own requests.
    public string ApproverGroup { get; set; } = "app1-approvers";

    public List<AppEntry> Apps { get; set; } = new();

    // Users who are permanent members of a managed group and are left alone by the drift check.
    // Production: empty. LAB-ONLY: "alice" (the phase 2 to 5 tests rely on her membership).
    public List<string> StandingMembers { get; set; } = new();

    public int MinDurationMinutes { get; set; } = 60;
    public int MaxDurationMinutes { get; set; } = 240;
    public int PendingTimeoutHours { get; set; } = 24;
    public int ReconcileSeconds { get; set; } = 30;

    // What to do with a managed-group member who has no active grant: "remove" or "alert".
    public string DriftAction { get; set; } = "remove";

    public string TicketPattern { get; set; } = "^[A-Z][A-Z0-9]{1,9}-[0-9]{1,7}$";

    // LAB-ONLY: also accept Keycloak access tokens with this audience as Bearer tokens, so the
    // tests can drive the API without a browser. Off in production.
    public bool AcceptBearer { get; set; }
    public string BearerAudience { get; set; } = "portal";

    public string DataDir { get; set; } = "/data";
    public string AuditLogPath { get; set; } = "/var/log/portal/portal-audit.log";

    public string RealmName => Authority.TrimEnd('/').Split('/').Last();

    public Uri AdminBase
    {
        get
        {
            var u = new Uri(Authority);
            return new Uri($"{u.Scheme}://{u.Authority}/admin/realms/{RealmName}/");
        }
    }

    public Uri TokenEndpoint => new(Authority.TrimEnd('/') + "/protocol/openid-connect/token");

    public static string ReadSecret(string path) =>
        File.Exists(path) ? File.ReadAllText(path).Trim() : throw new InvalidOperationException($"secret file {path} is missing");
}

public sealed class AppEntry
{
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public string Description { get; set; } = "";
    // Keycloak group that OpenBao maps to the app's read-only database roles.
    public string Group { get; set; } = "";
}
