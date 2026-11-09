using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Kella.Core;
using Kella.Core.Domain;
using Kella.Core.Events;
using Kella.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Kella.Infrastructure.Pipeline;

public sealed class BaselineWriterService(
    IServiceScopeFactory scopes,
    IBaselineProvider baselineProvider,
    ILogger<BaselineWriterService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await ComputeBaselinesAsync(stoppingToken);
            }
            catch (Exception ex) when (!stoppingToken.IsCancellationRequested)
            {
                logger.LogError(ex, "Failed to compute baselines.");
            }

            try
            {
                await Task.Delay(TimeSpan.FromHours(1), stoppingToken);
            }
            catch (OperationCanceledException) { break; }
        }
    }

    public async Task ComputeBaselinesAsync(CancellationToken ct = default)
    {
        using var scope = scopes.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<KellaDbContext>();

        var since = DateTimeOffset.UtcNow.AddDays(-30);
        var events = await db.Events
            .IgnoreQueryFilters()
            .Where(e => e.Module == Modules.Mail && e.Type == EventTypes.MailMessageQueued && e.Ts >= since)
            .Select(e => new { e.OrganizationId, e.ServerId, e.Ts, e.Attrs })
            .ToListAsync(ct);

        var bySender = events
            .Where(e => e.Attrs.TryGetValue("sender", out var s) && !string.IsNullOrWhiteSpace(s))
            .GroupBy(e => (
                e.OrganizationId,
                e.ServerId,
                Sender: e.Attrs["sender"].Trim().ToLowerInvariant()
            ));

        foreach (var group in bySender)
        {
            var minTs = group.Min(e => e.Ts);
            var maxTs = group.Max(e => e.Ts);

            // SPEC §9: until 24 h of data exist -> no baseline row
            if ((maxTs - minTs) < TimeSpan.FromHours(24))
                continue;

            var entityKey = $"{group.Key.ServerId}:{group.Key.Sender}";

            // Group into 10-minute buckets:
            var tenMinuteBuckets = group
                .GroupBy(e =>
                {
                    var utc = e.Ts.UtcDateTime;
                    long bucketId = new DateTimeOffset(utc).ToUnixTimeSeconds() / 600;
                    int dayIndex = ((int)utc.DayOfWeek + 6) % 7; // Monday=0 ... Sunday=6
                    int hourOfWeek = (dayIndex * 24) + utc.Hour;
                    return (HourOfWeek: hourOfWeek, BucketId: bucketId);
                })
                .Select(g => new { g.Key.HourOfWeek, Count = g.Count() })
                .GroupBy(b => b.HourOfWeek);

            foreach (var hourGroup in tenMinuteBuckets)
            {
                var hourOfWeek = hourGroup.Key;
                var counts = hourGroup.Select(x => (double)x.Count).OrderBy(x => x).ToList();
                if (counts.Count == 0) continue;

                int p50Idx = (int)Math.Ceiling(0.50 * counts.Count) - 1;
                int p95Idx = (int)Math.Ceiling(0.95 * counts.Count) - 1;
                double p50 = counts[Math.Clamp(p50Idx, 0, counts.Count - 1)];
                double p95 = counts[Math.Clamp(p95Idx, 0, counts.Count - 1)];

                var existing = await db.Baselines.IgnoreQueryFilters().FirstOrDefaultAsync(
                    b => b.OrganizationId == group.Key.OrganizationId &&
                         b.EntityKind == "mailbox" &&
                         b.EntityId == entityKey &&
                         b.HourOfWeek == hourOfWeek, ct);

                if (existing != null)
                {
                    existing.P50 = p50;
                    existing.P95 = p95;
                    existing.UpdatedAt = DateTimeOffset.UtcNow;
                }
                else
                {
                    db.Baselines.Add(new Baseline
                    {
                        OrganizationId = group.Key.OrganizationId,
                        EntityKind = "mailbox",
                        EntityId = entityKey,
                        HourOfWeek = hourOfWeek,
                        P50 = p50,
                        P95 = p95,
                        UpdatedAt = DateTimeOffset.UtcNow
                    });
                }

                baselineProvider.UpdateCache(group.Key.OrganizationId, "mailbox", entityKey, hourOfWeek, p95);
            }
        }

        await db.SaveChangesAsync(ct);
    }
}
