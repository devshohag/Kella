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

public sealed class SenderBucketRow
{
    public Guid OrganizationId { get; set; }
    public Guid ServerId { get; set; }
    public string Sender { get; set; } = "";
    public long BucketId { get; set; }
    public int HourOfWeek { get; set; }
    public int Count { get; set; }
    public DateTimeOffset MinTs { get; set; }
    public DateTimeOffset MaxTs { get; set; }
}

public sealed class BaselineWriterService(
    IServiceScopeFactory scopes,
    IBaselineProvider baselineProvider,
    ILogger<BaselineWriterService> logger) : BackgroundService
{
    public const string BucketAggregationSql = """
        SELECT 
            e."OrganizationId",
            e."ServerId",
            LOWER(COALESCE(NULLIF(e."Attrs"->>'sasl_username', ''), e."Attrs"->>'sender')) AS "Sender",
            FLOOR(EXTRACT(EPOCH FROM e."Ts") / 600)::bigint AS "BucketId",
            (((EXTRACT(DOW FROM e."Ts" AT TIME ZONE 'UTC')::int + 6) % 7) * 24 + EXTRACT(HOUR FROM e."Ts" AT TIME ZONE 'UTC')::int) AS "HourOfWeek",
            COUNT(*)::int AS "Count",
            MIN(e."Ts") AS "MinTs",
            MAX(e."Ts") AS "MaxTs"
        FROM events e
        WHERE e."Module" = 'mail'
          AND e."Type" = 'mail.message_queued'
          AND e."Ts" >= {0}
          AND LOWER(e."Attrs"->>'authenticated') = 'true'
          AND COALESCE(NULLIF(e."Attrs"->>'sasl_username', ''), e."Attrs"->>'sender') IS NOT NULL
        GROUP BY e."OrganizationId", e."ServerId", 3, 4, 5
        """;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // SPEC §9: Call PopulateFromDatabase for all orgs at startup
        try
        {
            using var scope = scopes.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<KellaDbContext>();
            var orgs = await db.Organizations.IgnoreQueryFilters().Select(o => o.Id).ToListAsync(stoppingToken);
            foreach (var orgId in orgs)
            {
                baselineProvider.PopulateFromDatabase(orgId);
            }
        }
        catch (Exception ex) when (!stoppingToken.IsCancellationRequested)
        {
            logger.LogError(ex, "Failed to initialize baselines from database at startup.");
        }

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

        List<SenderBucketRow> buckets;
        if (db.Database.IsRelational())
        {
            buckets = await db.Database.SqlQueryRaw<SenderBucketRow>(BucketAggregationSql, since).ToListAsync(ct);
        }
        else
        {
            var bucketsMap = new Dictionary<(Guid OrgId, Guid ServerId, string Sender, long BucketId), SenderBucketRow>();
            await foreach (var e in db.Events
                .IgnoreQueryFilters()
                .Where(e => e.Module == Modules.Mail && e.Type == EventTypes.MailMessageQueued && e.Ts >= since)
                .AsAsyncEnumerable()
                .WithCancellation(ct))
            {
                if (!e.Attrs.TryGetValue("authenticated", out var auth) || !string.Equals(auth, "true", StringComparison.OrdinalIgnoreCase))
                    continue;

                string sender = "";
                if (e.Attrs.TryGetValue("sasl_username", out var su) && !string.IsNullOrWhiteSpace(su))
                    sender = su.Trim().ToLowerInvariant();
                else if (e.Attrs.TryGetValue("sender", out var s) && !string.IsNullOrWhiteSpace(s))
                    sender = s.Trim().ToLowerInvariant();

                if (string.IsNullOrWhiteSpace(sender))
                    continue;

                long bucketId = e.Ts.ToUnixTimeSeconds() / 600;
                var key = (e.OrganizationId, e.ServerId, sender, bucketId);
                if (bucketsMap.TryGetValue(key, out var row))
                {
                    row.Count++;
                    if (e.Ts > row.MaxTs) row.MaxTs = e.Ts;
                    if (e.Ts < row.MinTs) row.MinTs = e.Ts;
                }
                else
                {
                    var utc = e.Ts.UtcDateTime;
                    int dayIndex = ((int)utc.DayOfWeek + 6) % 7;
                    int hourOfWeek = (dayIndex * 24) + utc.Hour;
                    bucketsMap[key] = new SenderBucketRow
                    {
                        OrganizationId = e.OrganizationId,
                        ServerId = e.ServerId,
                        Sender = sender,
                        BucketId = bucketId,
                        HourOfWeek = hourOfWeek,
                        Count = 1,
                        MinTs = e.Ts,
                        MaxTs = e.Ts
                    };
                }
            }
            buckets = bucketsMap.Values.ToList();
        }

        // Exclude buckets that already triggered an outbound_spike incident
        var spikeFindings = await db.Findings
            .IgnoreQueryFilters()
            .Where(f => f.RuleCode == "mail.outbound_spike" && f.IncidentId != null)
            .ToListAsync(ct);

        if (spikeFindings.Count > 0)
        {
            var excludedSpikes = spikeFindings.Select(f =>
            {
                string sender = "";
                if (f.Evidence.TryGetValue("sender", out var s) && !string.IsNullOrWhiteSpace(s))
                    sender = s.Trim().ToLowerInvariant();

                long startBucket = f.FirstSeen.AddMinutes(-10).ToUnixTimeSeconds() / 600;
                long endBucket = f.LastSeen.AddMinutes(1).ToUnixTimeSeconds() / 600;
                return (f.OrganizationId, f.ServerId, Sender: sender, StartBucket: startBucket, EndBucket: endBucket);
            }).ToList();

            buckets = buckets.Where(b => !excludedSpikes.Any(s =>
                s.OrganizationId == b.OrganizationId &&
                s.ServerId == b.ServerId &&
                s.Sender == b.Sender &&
                b.BucketId >= s.StartBucket &&
                b.BucketId <= s.EndBucket
            )).ToList();
        }

        var bySender = buckets.GroupBy(b => (b.OrganizationId, b.ServerId, b.Sender));

        foreach (var group in bySender)
        {
            var minTs = group.Min(e => e.MinTs);
            var maxTs = group.Max(e => e.MaxTs);

            // SPEC §9: until 24 h of data exist -> no baseline row
            if ((maxTs - minTs) < TimeSpan.FromHours(24))
                continue;

            var entityKey = $"{group.Key.ServerId}:{group.Key.Sender}";

            var tenMinuteBuckets = group.GroupBy(b => b.HourOfWeek);

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
