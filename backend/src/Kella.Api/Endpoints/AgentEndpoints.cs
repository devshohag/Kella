using Microsoft.EntityFrameworkCore;
using Kella.Core;
using Kella.Core.Domain;
using Kella.Infrastructure;
using Kella.Infrastructure.Data;
using Kella.Infrastructure.Security;

namespace Kella.Api.Endpoints;

// ---- Contracts (SPEC §7, §8). Field names are an API contract with the Go agent. ----
public sealed record EnrollRequest(string EnrollmentKey, string Hostname, string Os, int CpuCount, int RamMb, string? PublicIp, string AgentVersion);
public sealed record EnrollResponse(Guid ServerId, string AgentToken);
public sealed record FactsRequest(List<string> Detected, List<string> Guards);
public sealed record AgentEventDto(string Id, DateTimeOffset Ts, string Module, string Type, string Severity, string? SourceIp, Dictionary<string, string>? Attrs);
public sealed record EventBatch(string AgentVersion, Guid ServerId, DateTimeOffset SentAt, List<AgentEventDto> Events);
public sealed record CommandDto(Guid Id, string Kind, Dictionary<string, string> Params, DateTimeOffset ExpiresAt, string Signature);
public sealed record CommandAck(bool Ok, string? Output);

public static class AgentEndpoints
{
    public const int MaxEventsPerBatch = 1000;

    public static void MapAgentEndpoints(this WebApplication app)
    {
        var g = app.MapGroup("/api/agent").WithTags("Agent");

        g.MapPost("/enroll", EnrollAsync).AllowAnonymous();

        var authed = g.MapGroup("").AddEndpointFilter<AgentAuthFilter>();
        authed.MapPut("/facts", PutFactsAsync);
        authed.MapPost("/events", PostEventsAsync);
        authed.MapGet("/commands", GetCommandsAsync);
        authed.MapPost("/commands/{id:guid}/ack", AckCommandAsync);
    }

    private static async Task<IResult> EnrollAsync(EnrollRequest req, KellaDbContext db, OrgContext org, CancellationToken ct)
    {
        var keyHash = Tokens.Hash(req.EnrollmentKey);
        // Enrollment arrives without an organization, so this single lookup bypasses the org filter.
        var key = await db.EnrollmentKeys.IgnoreQueryFilters()
            .FirstOrDefaultAsync(k => k.KeyHash == keyHash && k.ExpiresAt > DateTimeOffset.UtcNow && k.UsesLeft > 0, ct);
        if (key is null) return Results.Problem("Enrollment key is invalid or expired.", statusCode: 401);

        org.Set(key.OrganizationId);
        key.UsesLeft--;

        var token = Tokens.Create("kat_");
        var server = new Server
        {
            OrganizationId = key.OrganizationId,
            Name = req.Hostname,
            Hostname = req.Hostname,
            Os = req.Os,
            CpuCount = req.CpuCount,
            RamMb = req.RamMb,
            PublicIp = req.PublicIp,
            AgentVersion = req.AgentVersion,
            KeyHash = Tokens.Hash(token),
            Status = ServerStatus.Online,
            LastSeenAt = DateTimeOffset.UtcNow,
        };
        db.Servers.Add(server);
        db.AuditLog.Add(new AuditEntry
        {
            OrganizationId = key.OrganizationId, ActorType = "agent", ActorId = server.Id.ToString(),
            Verb = "server.enrolled", Target = $"server:{server.Id}",
        });
        await db.SaveChangesAsync(ct);
        return Results.Ok(new EnrollResponse(server.Id, token));
    }

    private static async Task<IResult> PutFactsAsync(FactsRequest req, HttpContext http, KellaDbContext db, CancellationToken ct)
    {
        var server = AgentAuthFilter.CurrentServer(http);
        var tracked = await db.Servers.FirstAsync(s => s.Id == server.Id, ct);
        tracked.Detected = req.Detected;
        tracked.Guards = req.Guards;
        tracked.UpdatedAt = DateTimeOffset.UtcNow;
        await db.SaveChangesAsync(ct);
        return Results.NoContent();
    }

    private static async Task<IResult> PostEventsAsync(EventBatch batch, HttpContext http, IEventBus bus, KellaDbContext db, CancellationToken ct)
    {
        var server = AgentAuthFilter.CurrentServer(http);
        if (batch.ServerId != server.Id) return Results.Problem("serverId does not match token.", statusCode: 403);
        if (batch.Events.Count > MaxEventsPerBatch) return Results.Problem($"Max {MaxEventsPerBatch} events per batch.", statusCode: 413);

        var accepted = 0;
        foreach (var e in batch.Events)
        {
            if (string.IsNullOrWhiteSpace(e.Type) || string.IsNullOrWhiteSpace(e.Module)) continue;
            var evt = new KellaEvent
            {
                OrganizationId = server.OrganizationId,
                ServerId = server.Id,
                Ts = e.Ts,
                Module = e.Module,
                Type = e.Type,
                Severity = Enum.TryParse<Severity>(e.Severity, true, out var sev) ? sev : Severity.Info,
                SourceIp = e.SourceIp,
                Attrs = e.Attrs ?? [],
            };
            // TODO(Phase 2): resolve TenantId from Attrs (mailbox/site/domain) via the assets table.
            await bus.PublishAsync(evt, ct);
            accepted++;
        }

        var tracked = await db.Servers.FirstAsync(s => s.Id == server.Id, ct);
        tracked.LastSeenAt = DateTimeOffset.UtcNow;
        tracked.Status = ServerStatus.Online;
        tracked.AgentVersion = batch.AgentVersion;
        await db.SaveChangesAsync(ct);

        return Results.Ok(new { accepted });
    }

    /// <summary>Long-poll: returns as soon as commands exist, or an empty list after <paramref name="wait"/> seconds.</summary>
    private static async Task<IResult> GetCommandsAsync(HttpContext http, KellaDbContext db, int? wait, CancellationToken ct)
    {
        var server = AgentAuthFilter.CurrentServer(http);
        var deadline = DateTimeOffset.UtcNow.AddSeconds(Math.Clamp(wait ?? 0, 0, 30));

        while (true)
        {
            var now = DateTimeOffset.UtcNow;
            var cmds = await db.AgentCommands
                .Where(c => c.ServerId == server.Id && c.Status == "queued" && c.ExpiresAt > now)
                .OrderBy(c => c.CreatedAt).Take(50).ToListAsync(ct);

            if (cmds.Count > 0 || now >= deadline)
            {
                foreach (var c in cmds) { c.Status = "sent"; c.FetchedAt = now; }
                await db.SaveChangesAsync(ct);
                return Results.Ok(cmds.Select(c => new CommandDto(c.Id, c.Kind, c.Params, c.ExpiresAt, c.Signature)));
            }
            await Task.Delay(1000, ct);
        }
    }

    private static async Task<IResult> AckCommandAsync(Guid id, CommandAck ack, HttpContext http, KellaDbContext db, CancellationToken ct)
    {
        var server = AgentAuthFilter.CurrentServer(http);
        var cmd = await db.AgentCommands.FirstOrDefaultAsync(c => c.Id == id && c.ServerId == server.Id, ct);
        if (cmd is null) return Results.NotFound();

        cmd.Status = ack.Ok ? "succeeded" : "failed";
        cmd.AckedAt = DateTimeOffset.UtcNow;

        var action = await db.Actions.FirstOrDefaultAsync(a => a.Id == cmd.ActionId, ct);
        if (action is not null)
        {
            action.Status = ack.Ok ? ActionStatus.Succeeded : ActionStatus.Failed;
            action.ExecutedAt = DateTimeOffset.UtcNow;
            action.ResultJson = System.Text.Json.JsonSerializer.Serialize(ack);
            db.AuditLog.Add(new AuditEntry
            {
                OrganizationId = server.OrganizationId, ActorType = "agent", ActorId = server.Id.ToString(),
                Verb = $"action.{cmd.Status}", Target = $"action:{action.Id}", DataJson = action.ResultJson,
            });
        }
        await db.SaveChangesAsync(ct);
        return Results.NoContent();
    }
}

/// <summary>Authenticates "Authorization: Bearer kat_…" agent tokens and sets the organization for the request.</summary>
public sealed class AgentAuthFilter(KellaDbContext db, OrgContext org) : IEndpointFilter
{
    private const string ItemKey = "kella.server";

    public static Server CurrentServer(HttpContext http) => (Server)http.Items[ItemKey]!;

    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext ctx, EndpointFilterDelegate next)
    {
        var header = ctx.HttpContext.Request.Headers.Authorization.ToString();
        if (!header.StartsWith("Bearer ", StringComparison.Ordinal)) return Results.Unauthorized();

        var hash = Tokens.Hash(header["Bearer ".Length..].Trim());
        // Agent requests carry no organization yet; the token identifies it. Only bypass of the org filter in the API.
        var server = await db.Servers.IgnoreQueryFilters().AsNoTracking()
            .FirstOrDefaultAsync(s => s.KeyHash == hash && s.Status != ServerStatus.Disabled);
        if (server is null) return Results.Unauthorized();

        org.Set(server.OrganizationId);
        ctx.HttpContext.Items[ItemKey] = server;
        return await next(ctx);
    }
}
