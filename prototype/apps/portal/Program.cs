using System.Net.Sockets;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Portal;

// Phase 6: access approval portal (design 4.C). See README "Phase 6" and compose.phase6.yaml.
var builder = WebApplication.CreateBuilder(args);

var opts = builder.Configuration.GetSection("Portal").Get<PortalOptions>() ?? new PortalOptions();
if (string.IsNullOrWhiteSpace(opts.Authority)) throw new InvalidOperationException("Portal:Authority is not set");
if (opts.Apps.Count == 0) throw new InvalidOperationException("Portal:Apps is empty");
builder.Services.AddSingleton(opts);

// Back-channel to Keycloak (discovery, keys, code exchange, admin API). The issuer host
// (keycloak.localhost) is mapped to IdpConnectHost at connect time; TLS and Host stay as issued.
SocketsHttpHandler IdpHandler()
{
    var h = new SocketsHttpHandler { ConnectTimeout = TimeSpan.FromSeconds(5), PooledConnectionLifetime = TimeSpan.FromMinutes(5) };
    if (!string.IsNullOrWhiteSpace(opts.IdpConnectHost))
    {
        var issuerHost = new Uri(opts.Authority).Host;
        h.ConnectCallback = async (ctx, ct) =>
        {
            var host = string.Equals(ctx.DnsEndPoint.Host, issuerHost, StringComparison.OrdinalIgnoreCase) ? opts.IdpConnectHost : ctx.DnsEndPoint.Host;
            var s = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            try { await s.ConnectAsync(host, ctx.DnsEndPoint.Port, ct); return new NetworkStream(s, ownsSocket: true); }
            catch { s.Dispose(); throw; }
        };
    }
    return h;
}
builder.Services.AddHttpClient("idp", c => c.Timeout = TimeSpan.FromSeconds(10)).ConfigurePrimaryHttpMessageHandler(IdpHandler);

// Keys for the session cookie survive restarts (portal-data volume).
builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(opts.DataDir, "keys")))
    .SetApplicationName("portal");

// LAB-ONLY: Keycloak runs in dev mode over plain HTTP.
var requireHttps = opts.Authority.StartsWith("https://", StringComparison.OrdinalIgnoreCase);
const string Smart = "smart";

builder.Services.AddAuthentication(o =>
    {
        o.DefaultScheme = Smart;
        o.DefaultChallengeScheme = Smart;
    })
    .AddPolicyScheme(Smart, null, o => o.ForwardDefaultSelector = ctx =>
        opts.AcceptBearer && ctx.Request.Headers.Authorization.ToString().StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
            ? JwtBearerDefaults.AuthenticationScheme
            : CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(o =>
    {
        o.Cookie.Name = "portal_session";
        o.Cookie.HttpOnly = true;
        o.Cookie.SameSite = SameSiteMode.Lax;
        o.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
        // Group membership (approver or not) is read at sign-in; a short session bounds how long
        // a removed approver keeps the role here.
        o.ExpireTimeSpan = TimeSpan.FromMinutes(30);
        o.SlidingExpiration = false;
        o.LoginPath = "/signin";
        o.Events.OnRedirectToLogin = ctx =>
        {
            if (ctx.Request.Path.StartsWithSegments("/api")) ctx.Response.StatusCode = 401;
            else ctx.Response.Redirect(ctx.RedirectUri);
            return Task.CompletedTask;
        };
        o.Events.OnRedirectToAccessDenied = ctx => { ctx.Response.StatusCode = 403; return Task.CompletedTask; };
    })
    .AddOpenIdConnect(o =>
    {
        o.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        o.Authority = opts.Authority;
        o.RequireHttpsMetadata = requireHttps;
        o.ClientId = opts.ClientId;
        o.ClientSecret = PortalOptions.ReadSecret(opts.ClientSecretFile);
        o.ResponseType = OpenIdConnectResponseType.Code;
        // Query response mode: the correlation and nonce cookies can stay SameSite=Lax over HTTP.
        o.ResponseMode = OpenIdConnectResponseMode.Query;
        o.UsePkce = true;
        o.Scope.Clear();
        o.Scope.Add("openid");
        o.Scope.Add("profile");
        o.MapInboundClaims = false;
        o.GetClaimsFromUserInfoEndpoint = false;
        o.SaveTokens = false;
        o.CorrelationCookie.SameSite = SameSiteMode.Lax;
        o.CorrelationCookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
        o.NonceCookie.SameSite = SameSiteMode.Lax;
        o.NonceCookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
        o.TokenValidationParameters.NameClaimType = "preferred_username";
        o.TokenValidationParameters.RoleClaimType = "groups";
        o.Backchannel = new HttpClient(IdpHandler()) { Timeout = TimeSpan.FromSeconds(10) };
    })
    .AddJwtBearer(o =>
    {
        // LAB-ONLY path (Portal:AcceptBearer): tokens of the test client "portal-test".
        o.Authority = opts.Authority;
        o.RequireHttpsMetadata = requireHttps;
        o.Audience = opts.BearerAudience;
        o.MapInboundClaims = false;
        o.TokenValidationParameters.NameClaimType = "preferred_username";
        o.TokenValidationParameters.RoleClaimType = "groups";
        o.Backchannel = new HttpClient(IdpHandler()) { Timeout = TimeSpan.FromSeconds(10) };
    });
builder.Services.AddAuthorization();

builder.Services.AddSingleton<Store>();
builder.Services.AddSingleton<AuditLog>();
builder.Services.AddSingleton<KeycloakGroups>();
builder.Services.AddSingleton<AccessService>();
builder.Services.AddHostedService<ExpiryWorker>();

var app = builder.Build();

app.Use(async (ctx, next) =>
{
    var h = ctx.Response.Headers;
    h["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'";
    h["X-Content-Type-Options"] = "nosniff";
    h["Referrer-Policy"] = "no-referrer";
    h["X-Frame-Options"] = "DENY";
    if (ctx.Request.Path.StartsWithSegments("/api")) h["Cache-Control"] = "no-store";
    await next();
});

app.UseDefaultFiles();
app.UseStaticFiles();
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/healthz", () => Results.Ok(new { status = "ok" }));

// Readiness: the service account can get a token and see the managed groups.
app.MapGet("/readyz", async (KeycloakGroups kc, CancellationToken ct) =>
{
    try
    {
        foreach (var g in opts.Apps.Select(a => a.Group).Distinct()) await kc.GroupId(g, ct, fresh: true);
        return Results.Ok(new { status = "ready" });
    }
    catch (Exception ex) { return Results.Json(new { status = "not ready", error = ex.Message }, statusCode: 503); }
});

app.MapGet("/signin", (string? returnUrl) =>
{
    var target = returnUrl is not null && returnUrl.StartsWith('/') && !returnUrl.StartsWith("//") && !returnUrl.StartsWith("/\\") ? returnUrl : "/";
    return Results.Challenge(new AuthenticationProperties { RedirectUri = target }, [OpenIdConnectDefaults.AuthenticationScheme]);
});

app.MapGet("/signout", async (HttpContext ctx) =>
{
    await ctx.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    // Keycloak's own session ends too (it asks for confirmation without an id_token_hint).
    var back = $"{ctx.Request.Scheme}://{ctx.Request.Host}/";
    var url = $"{opts.Authority.TrimEnd('/')}/protocol/openid-connect/logout?client_id={Uri.EscapeDataString(opts.ClientId)}&post_logout_redirect_uri={Uri.EscapeDataString(back)}";
    return Results.Redirect(url);
});

var api = app.MapGroup("/api").RequireAuthorization();

// Cross-site request forgery: every state change needs a custom header. A browser sends one
// cross-origin only after a CORS preflight, which this API never answers.
api.AddEndpointFilter(async (ctx, next) =>
{
    var req = ctx.HttpContext.Request;
    if (!HttpMethods.IsGet(req.Method) && req.Headers["X-Portal-Request"] != "1")
        return Results.Json(new { error = "missing X-Portal-Request header" }, statusCode: 400);
    return await next(ctx);
});

Caller Who(HttpContext ctx)
{
    var u = ctx.User;
    var sub = u.FindFirstValue("sub") ?? throw new InvalidOperationException("token without sub");
    var username = u.FindFirstValue("preferred_username") ?? sub;
    var name = u.FindFirstValue("name") ?? username;
    var approver = u.FindAll("groups").Any(c => c.Value == opts.ApproverGroup || c.Value == "/" + opts.ApproverGroup);
    return new Caller(sub, username, name, approver, ctx.Connection.RemoteIpAddress?.ToString());
}

IResult Send(Outcome o) => Results.Json(o.Body, statusCode: o.Status);

api.MapGet("/me", (HttpContext ctx) =>
{
    var c = Who(ctx);
    return Results.Ok(new
    {
        username = c.Username,
        name = c.DisplayName,
        isApprover = c.IsApprover,
        approverGroup = opts.ApproverGroup,
        apps = opts.Apps.Select(a => new { a.Id, a.Name, a.Description, a.Group }),
        minDurationMinutes = opts.MinDurationMinutes,
        maxDurationMinutes = opts.MaxDurationMinutes,
        ticketExample = "OPS-1234",
    });
});

api.MapGet("/requests", (HttpContext ctx, AccessService svc, string? scope) =>
{
    var c = Who(ctx);
    if (scope == "all")
        return c.IsApprover ? Results.Ok(svc.All(c)) : Results.Json(new { error = "approvers only" }, statusCode: 403);
    return Results.Ok(svc.Mine(c));
});

api.MapGet("/requests/{id}/history", (string id, HttpContext ctx, AccessService svc) => Send(svc.History(id, Who(ctx))));

api.MapPost("/requests", async (CreateBody body, HttpContext ctx, AccessService svc, CancellationToken ct) =>
    Send(await svc.Create(Who(ctx), body, ct)));

api.MapPost("/requests/{id}/approve", async (string id, DecisionBody? body, HttpContext ctx, AccessService svc, CancellationToken ct) =>
    Send(await svc.Approve(id, Who(ctx), body ?? new DecisionBody(null), ct)));

api.MapPost("/requests/{id}/deny", async (string id, DecisionBody? body, HttpContext ctx, AccessService svc, CancellationToken ct) =>
    Send(await svc.Deny(id, Who(ctx), body ?? new DecisionBody(null), ct)));

api.MapPost("/requests/{id}/cancel", async (string id, HttpContext ctx, AccessService svc, CancellationToken ct) =>
    Send(await svc.Cancel(id, Who(ctx), ct)));

api.MapPost("/requests/{id}/revoke", async (string id, DecisionBody? body, HttpContext ctx, AccessService svc, CancellationToken ct) =>
    Send(await svc.Revoke(id, Who(ctx), body ?? new DecisionBody(null), ct)));

app.Run();
