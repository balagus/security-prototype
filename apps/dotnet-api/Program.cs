using DotnetApi;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Npgsql;
using OpenTelemetry.Logs;
using OpenTelemetry.Metrics;
using OpenTelemetry.Trace;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);

// Docker secrets: /run/secrets/ConnectionStrings__App1 -> ConnectionStrings:App1.
// optional: true, so a missing directory does not crash startup.
builder.Configuration.AddKeyPerFile("/run/secrets", optional: true);

static void Configure(DbContextOptionsBuilder o, string cs) =>
    o.UseNpgsql(cs)
     // The hand-written migration has no model snapshot, so EF would otherwise
     // throw PendingModelChangesWarning inside Migrate().
     .ConfigureWarnings(w => w.Ignore(RelationalEventId.PendingModelChangesWarning));

static void MigrateWithRetry(string cs, TimeSpan timeout)
{
    var deadline = DateTime.UtcNow + timeout;
    while (true)
    {
        try
        {
            var ob = new DbContextOptionsBuilder<AppDbContext>();
            Configure(ob, cs);
            using var db = new AppDbContext(ob.Options);
            db.Database.Migrate();
            Console.WriteLine("Migrations applied.");
            return;
        }
        catch (Exception ex) when (DateTime.UtcNow < deadline)
        {
            Console.WriteLine($"Migration failed ({ex.GetType().Name}: {ex.Message}); retrying in 2s...");
            Thread.Sleep(2000);
        }
    }
}

// One-shot migrate mode: `dotnet-api migrate`
if (args.Length == 1 && args[0] == "migrate")
{
    var cs = builder.Configuration["ConnectionStrings:Migrator"];
    if (string.IsNullOrWhiteSpace(cs)) cs = builder.Configuration["ConnectionStrings:App1"];
    if (string.IsNullOrWhiteSpace(cs))
    {
        Console.Error.WriteLine("No ConnectionStrings:Migrator or ConnectionStrings:App1 configured.");
        return 1;
    }
    try
    {
        MigrateWithRetry(cs, TimeSpan.FromSeconds(60));
        return 0;
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"Migration failed: {ex}");
        return 1;
    }
}

var appCs = builder.Configuration["ConnectionStrings:App1"];
if (string.IsNullOrWhiteSpace(appCs))
{
    Console.Error.WriteLine("ConnectionStrings:App1 is not configured.");
    return 1;
}

builder.Services.AddDbContext<AppDbContext>(o => Configure(o, appCs));
builder.Services.ConfigureHttpJsonOptions(o =>
    o.SerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower);

// Debug telemetry over OTLP, only when OTEL_EXPORTER_OTLP_ENDPOINT is set (without it nothing is
// sent; migrate mode above never gets here). The exporter, service
// name and resource attributes come from the standard OTEL_* environment variables.
// No PII: no request bodies, no query strings (url.query removed), SQL text is EF Core's
// parameterized command (Npgsql records no parameter values), handlers log no customer fields.
// Alloy redacts again before anything is stored (config/telemetry/alloy/config.alloy).
if (!string.IsNullOrWhiteSpace(builder.Configuration["OTEL_EXPORTER_OTLP_ENDPOINT"]))
{
    var otel = builder.Services.AddOpenTelemetry()
        .WithTracing(t => t
            .AddAspNetCoreInstrumentation(o =>
            {
                o.RecordException = true;
                o.Filter = ctx => !ctx.Request.Path.StartsWithSegments("/health");
                o.EnrichWithHttpRequest = (activity, _) => activity.SetTag("url.query", null);
            })
            .AddNpgsql()
            .AddOtlpExporter())
        .WithLogging(l => l.AddOtlpExporter(), o =>
        {
            o.IncludeFormattedMessage = true;
            o.IncludeScopes = false;
        });

    if (!string.Equals(builder.Configuration["OTEL_METRICS_EXPORTER"], "none", StringComparison.OrdinalIgnoreCase))
    {
        otel.WithMetrics(m => m.AddAspNetCoreInstrumentation().AddOtlpExporter());
    }
}

var app = builder.Build();

if (string.Equals(builder.Configuration["RUN_MIGRATIONS_ON_STARTUP"], "true", StringComparison.OrdinalIgnoreCase))
{
    try
    {
        MigrateWithRetry(appCs, TimeSpan.FromSeconds(60));
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"Migration on startup failed: {ex}");
        return 1;
    }
}

app.MapGet("/health", async (AppDbContext db, CancellationToken ct) =>
{
    try
    {
        await db.Database.SqlQueryRaw<int>("SELECT 1 AS \"Value\"").ToListAsync(ct);
        return Results.Json(new { status = "ok", db = "ok" });
    }
    catch (Exception)
    {
        return Results.Json(new { status = "degraded", db = "down" }, statusCode: 503);
    }
});

// Log lines carry only counts and ids, never customer fields (they go to the debug telemetry).
app.MapGet("/api/customers", async (AppDbContext db, ILogger<Program> log, CancellationToken ct) =>
{
    var list = await db.Customers.AsNoTracking().OrderBy(c => c.Id).ToListAsync(ct);
    log.LogInformation("Listed {Count} customers", list.Count);
    return Results.Ok(list);
});

app.MapPost("/api/customers", async (CustomerCreate? body, AppDbContext db, ILogger<Program> log, CancellationToken ct) =>
{
    var email = body?.Email?.Trim();
    var fullName = body?.FullName?.Trim();
    if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(fullName)
        || email.Length > 255 || fullName.Length > 255)
    {
        log.LogWarning("Customer create rejected: validation failed");
        return Results.Json(new { error = "email and full_name are required (max 255 chars)" }, statusCode: 400);
    }

    var c = new Customer { Email = email, FullName = fullName };
    db.Customers.Add(c);
    await db.SaveChangesAsync(ct);
    log.LogInformation("Created customer {CustomerId}", c.Id);
    return Results.Created($"/api/customers/{c.Id}", c);
});

app.MapGet("/api/orders", async (AppDbContext db, ILogger<Program> log, CancellationToken ct) =>
{
    var list = await db.Orders.AsNoTracking().OrderBy(o => o.Id).ToListAsync(ct);
    log.LogInformation("Listed {Count} orders", list.Count);
    return Results.Ok(list);
});

await app.RunAsync();
return 0;

record CustomerCreate(string? Email, string? FullName);
