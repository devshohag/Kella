using Kella.Core.Actions;
using Kella.Core.Domain;
using Kella.Core.Rules;
using Kella.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Kella.Infrastructure.Pipeline;

/// <summary>
/// Releases senders when their <c>hold_sender</c> TTL expires. The hold TTL travels in the action
/// params (<c>ttlSec</c>, default 4 hours) so it is visible in the incident timeline and audit log.
/// </summary>
public sealed class HoldExpiryService(
    IServiceScopeFactory scopes,
    IConfiguration config,
    ILogger<HoldExpiryService> log) : BackgroundService
{
    public TimeSpan CheckInterval => TimeSpan.FromSeconds(
        Math.Max(1, config.GetValue("Kella:Mail:HoldExpiryCheckSeconds", 60)));

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        using var timer = new PeriodicTimer(CheckInterval);
        while (await timer.WaitForNextTickAsync(ct))
        {
            try
            {
                var released = await CheckOnceAsync(ct);
                if (released > 0) log.LogInformation("Queued {Count} expired sender release(s)", released);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                log.LogError(ex, "Hold expiry check failed");
            }
        }
    }

    public async Task<int> CheckOnceAsync(CancellationToken ct = default)
    {
        List<Guid> organizations;
        using (var scope = scopes.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<KellaDbContext>();
            organizations = await db.Organizations.Select(o => o.Id).ToListAsync(ct);
        }

        var defaultTtl = config.GetValue("Kella:Mail:HoldTtlSeconds", SenderReleaseService.DefaultHoldTtlSeconds);
        var now = DateTimeOffset.UtcNow;
        var queued = 0;

        foreach (var organizationId in organizations)
        {
            using var scope = scopes.CreateScope();
            scope.ServiceProvider.GetRequiredService<OrgContext>().Set(organizationId);
            var db = scope.ServiceProvider.GetRequiredService<KellaDbContext>();
            var release = scope.ServiceProvider.GetRequiredService<SenderReleaseService>();

            var holds = await db.Actions
                .Where(a => a.Kind == ActionKinds.HoldSender && a.Status == ActionStatus.Succeeded)
                .ToListAsync(ct);

            foreach (var hold in holds)
            {
                var ttl = hold.Params.TryGetValue("ttlSec", out var raw) && int.TryParse(raw, out var parsed) && parsed > 0
                    ? parsed
                    : defaultTtl;
                var started = hold.ExecutedAt ?? hold.CreatedAt;
                if (started.AddSeconds(ttl) > now) continue;

                queued += await release.QueueForActionAsync(
                    hold.Id, "system", "hold.ttl", "hold_expiry", ct);
            }
        }

        return queued;
    }
}
