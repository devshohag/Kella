using Kella.Core;
using Kella.Core.Domain;
using Kella.Core.Events;
using Kella.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Kella.Infrastructure.Pipeline;

/// <summary>
/// Marks servers offline when no event has arrived within the configured window and opens one
/// <c>server.down</c> incident per outage (SPEC §9, §12). Recovery is handled at ingest.
/// </summary>
public sealed class ServerHealthMonitor(
    IServiceScopeFactory scopes,
    IConfiguration config,
    ILogger<ServerHealthMonitor> log) : BackgroundService
{
    public TimeSpan CheckInterval => TimeSpan.FromSeconds(
        Math.Max(1, config.GetValue("Kella:Monitoring:CheckIntervalSeconds", 30)));

    public TimeSpan DownAfter => TimeSpan.FromSeconds(
        Math.Max(1, config.GetValue("Kella:Monitoring:DownAfterSeconds", 180)));

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        using var timer = new PeriodicTimer(CheckInterval);
        while (await timer.WaitForNextTickAsync(ct))
        {
            try
            {
                var opened = await CheckOnceAsync(ct);
                if (opened > 0) log.LogWarning("Opened {Count} server.down incident(s)", opened);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                log.LogError(ex, "Server health check failed");
            }
        }
    }

    /// <summary>Runs one check across every organization. Returns the number of incidents opened.</summary>
    public async Task<int> CheckOnceAsync(CancellationToken ct)
    {
        List<Guid> organizations;
        using (var scope = scopes.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<KellaDbContext>();
            organizations = await db.Organizations.Select(o => o.Id).ToListAsync(ct);
        }

        var cutoff = DateTimeOffset.UtcNow - DownAfter;
        var opened = 0;

        foreach (var organizationId in organizations)
        {
            using var scope = scopes.CreateScope();
            scope.ServiceProvider.GetRequiredService<OrgContext>().Set(organizationId);
            var db = scope.ServiceProvider.GetRequiredService<KellaDbContext>();
            var router = scope.ServiceProvider.GetRequiredService<IAlertRouter>();

            var stale = await db.Servers
                .Where(s => s.Status == ServerStatus.Online && s.LastSeenAt != null && s.LastSeenAt < cutoff)
                .ToListAsync(ct);

            foreach (var server in stale)
            {
                var now = DateTimeOffset.UtcNow;
                server.Status = ServerStatus.Offline;
                server.UpdatedAt = now;

                var alreadyOpen = await db.Incidents.AnyAsync(i =>
                    i.ServerId == server.Id &&
                    i.Subtype == "server.down" &&
                    i.Status != IncidentStatus.Resolved, ct);
                if (alreadyOpen)
                {
                    await db.SaveChangesAsync(ct);
                    continue;
                }

                var incident = new Incident
                {
                    OrganizationId = organizationId,
                    ServerId = server.Id,
                    Type = "server",
                    Subtype = "server.down",
                    Severity = Severity.Down,
                    Title = $"Server {server.Name} stopped reporting",
                    Summary = $"No heartbeat from {server.Name} since {server.LastSeenAt:u}.",
                    OpenedAt = now,
                };
                db.Findings.Add(new Finding
                {
                    OrganizationId = organizationId,
                    RuleCode = "server.down",
                    ServerId = server.Id,
                    Severity = Severity.Down,
                    Title = incident.Title,
                    Summary = incident.Summary,
                    Evidence = new()
                    {
                        ["server"] = server.Name,
                        ["lastSeenAt"] = server.LastSeenAt?.ToString("O") ?? "",
                    },
                    FirstSeen = now,
                    LastSeen = now,
                    IncidentId = incident.Id,
                });
                db.AuditLog.Add(new AuditEntry
                {
                    OrganizationId = organizationId,
                    ActorType = "system",
                    ActorId = "server.down",
                    Verb = "incident.opened",
                    Target = $"incident:{incident.Id}",
                });
                await IncidentNumberAllocator.SaveIncidentWithRetryAsync(db, incident, ct);

                log.LogWarning("INC-{Number}: {Title}", incident.Number, incident.Title);
                await router.RouteAsync(incident, ct);
                opened++;
            }
        }

        return opened;
    }
}
