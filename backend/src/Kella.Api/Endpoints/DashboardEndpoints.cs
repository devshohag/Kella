using Microsoft.EntityFrameworkCore;
using Kella.Core.Domain;
using Kella.Infrastructure.Data;
using Kella.Infrastructure.Security;

namespace Kella.Api.Endpoints;

public sealed record OverviewDto(int ServersOnline, int ServersTotal, int Tenants, int OpenIncidents, int PendingApprovals, IReadOnlyList<IncidentListItem> ActiveIncidents);
public sealed record IncidentListItem(Guid Id, string Number, string Title, string Severity, string Status, DateTimeOffset OpenedAt);
public sealed record ServerListItem(Guid Id, string Name, string? PublicIp, string Status, IReadOnlyList<string> Detected, IReadOnlyList<string> Guards, DateTimeOffset? LastSeenAt);
public sealed record EnrollmentKeyResponse(string Key, DateTimeOffset ExpiresAt, string InstallCommand);

/// <summary>Dashboard API (SPEC §14). Requires an organization on the request (see DevOrgMiddleware / auth).</summary>
public static class DashboardEndpoints
{
    public static void MapDashboardEndpoints(this WebApplication app)
    {
        var g = app.MapGroup("/api").WithTags("Dashboard").AddEndpointFilter<RequireOrgFilter>();

        g.MapGet("/overview", async (KellaDbContext db, CancellationToken ct) =>
        {
            var servers = await db.Servers.ToListAsync(ct);
            var open = await db.Incidents.Where(i => i.Status != IncidentStatus.Resolved)
                .OrderByDescending(i => i.OpenedAt).Take(5).ToListAsync(ct);
            return new OverviewDto(
                servers.Count(s => s.Status == ServerStatus.Online),
                servers.Count,
                await db.Tenants.CountAsync(ct),
                await db.Incidents.CountAsync(i => i.Status != IncidentStatus.Resolved, ct),
                await db.Actions.CountAsync(a => a.Status == ActionStatus.PendingApproval, ct),
                open.Select(ToListItem).ToList());
        });

        g.MapGet("/servers", async (KellaDbContext db, CancellationToken ct) =>
            (await db.Servers.OrderBy(s => s.Name).ToListAsync(ct))
                .Select(s => new ServerListItem(s.Id, s.Name, s.PublicIp, s.Status.ToString(), s.Detected, s.Guards, s.LastSeenAt)));

        g.MapPost("/servers/enrollment-keys", async (KellaDbContext db, Infrastructure.OrgContext org, IConfiguration cfg, CancellationToken ct) =>
        {
            var key = Tokens.Create("kella_");
            var entity = new EnrollmentKey
            {
                OrganizationId = org.OrganizationId!.Value,
                KeyHash = Tokens.Hash(key),
                ExpiresAt = DateTimeOffset.UtcNow.AddHours(24),
                UsesLeft = 1,
            };
            db.EnrollmentKeys.Add(entity);
            await db.SaveChangesAsync(ct);
            var installUrl = cfg["Kella:InstallUrl"] ?? "https://get.example.com/install.sh";
            return new EnrollmentKeyResponse(key, entity.ExpiresAt, $"curl -sSL {installUrl} | sudo sh -s -- --key {key}");
        });

        g.MapGet("/incidents", async (KellaDbContext db, string? status, CancellationToken ct) =>
        {
            var q = db.Incidents.AsQueryable();
            if (Enum.TryParse<IncidentStatus>(status, true, out var st)) q = q.Where(i => i.Status == st);
            return (await q.OrderByDescending(i => i.OpenedAt).Take(200).ToListAsync(ct)).Select(ToListItem);
        });

        g.MapGet("/incidents/{id:guid}", async (Guid id, KellaDbContext db, CancellationToken ct) =>
        {
            var inc = await db.Incidents.FirstOrDefaultAsync(i => i.Id == id, ct);
            if (inc is null) return Results.NotFound();
            var findings = await db.Findings.Where(f => f.IncidentId == id).ToListAsync(ct);
            var actions = await db.Actions.Where(a => a.IncidentId == id).ToListAsync(ct);
            return Results.Ok(new { incident = ToListItem(inc), inc.Summary, findings, actions });
        });

        g.MapPost("/actions/{id:guid}/approve", async (Guid id, KellaDbContext db, CancellationToken ct) =>
        {
            var action = await db.Actions.FirstOrDefaultAsync(a => a.Id == id, ct);
            if (action is null) return Results.NotFound();
            if (action.Status != ActionStatus.PendingApproval) return Results.Problem("Action is not waiting for approval.", statusCode: 409);
            if (action.ExpiresAt < DateTimeOffset.UtcNow) { action.Status = ActionStatus.Expired; await db.SaveChangesAsync(ct); return Results.Problem("Approval expired.", statusCode: 410); }

            action.Status = ActionStatus.Queued;
            action.ApprovedBy = "dev-user"; // TODO(Phase 0): current user id from auth
            db.AgentCommands.Add(new AgentCommand
            {
                ServerId = action.ServerId, ActionId = action.Id, Kind = action.Kind,
                Params = new(action.Params), ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(10),
            });
            db.AuditLog.Add(new AuditEntry
            {
                OrganizationId = action.OrganizationId, ActorType = "user", ActorId = action.ApprovedBy,
                Verb = "action.approved", Target = $"action:{action.Id}",
            });
            await db.SaveChangesAsync(ct);
            return Results.NoContent();
        });
    }

    private static IncidentListItem ToListItem(Incident i) =>
        new(i.Id, $"INC-{i.Number}", i.Title, i.Severity.ToString(), i.Status.ToString(), i.OpenedAt);
}

public sealed class RequireOrgFilter(Infrastructure.OrgContext org) : IEndpointFilter
{
    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext ctx, EndpointFilterDelegate next) =>
        org.OrganizationId is null ? Results.Unauthorized() : await next(ctx);
}
