using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Threading;
using System.Threading.Tasks;
using Kella.Core;
using Kella.Core.Domain;
using Kella.Core.Events;
using Kella.Infrastructure;
using Kella.Infrastructure.Data;
using Kella.Infrastructure.Pipeline;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Kella.Tests;

public class BaselineWriterOptimizationTests
{
    private sealed class QueryShapeInterceptor : IQueryExpressionInterceptor
    {
        public bool GroupByFound { get; private set; }

        public Expression QueryCompilationStarting(Expression queryExpression, QueryExpressionEventData eventData)
        {
            var text = queryExpression.ToString();
            // If the query is querying Events
            if (text.Contains("KellaEvent") || text.Contains("events"))
            {
                if (text.Contains("GroupBy"))
                {
                    GroupByFound = true;
                }
                else
                {
                    throw new InvalidOperationException(
                        $"Memory-heavy ToList query shape detected! Query on events does not use GroupBy: {text}");
                }
            }
            return queryExpression;
        }
    }

    [Fact]
    public async Task BaselineWriter_does_not_use_memory_heavy_tolist_on_50k_events()
    {
        // Assert SQL query shape computes per-sender 10-minute buckets in SQL using GROUP BY
        Assert.Contains("GROUP BY", BaselineWriterService.BucketAggregationSql);
        Assert.Contains("FLOOR(EXTRACT(EPOCH FROM", BaselineWriterService.BucketAggregationSql);
        Assert.Contains("mail.message_queued", BaselineWriterService.BucketAggregationSql);

        var dbName = $"kella-shape-{Guid.NewGuid():N}";
        var options = new DbContextOptionsBuilder<KellaDbContext>()
            .UseInMemoryDatabase(dbName)
            .Options;

        var orgId = Guid.NewGuid();
        var serverId = Guid.NewGuid();
        var orgContext = new OrgContext();

        using (var db = new KellaDbContext(options, orgContext))
        {
            db.Organizations.Add(new Organization { Id = orgId, Name = "Org 50k" });
            db.Servers.Add(new Server { Id = serverId, OrganizationId = orgId, Name = "srv-1" });

            // Seed 50,000 events spanning 3 days
            var start = DateTimeOffset.UtcNow.AddDays(-3);
            var events = new List<KellaEvent>(50000);
            for (int i = 0; i < 50000; i++)
            {
                events.Add(new KellaEvent
                {
                    Id = Guid.CreateVersion7(),
                    OrganizationId = orgId,
                    ServerId = serverId,
                    Ts = start.AddSeconds(i * 5),
                    Module = Modules.Mail,
                    Type = EventTypes.MailMessageQueued,
                    Attrs = new() { ["sender"] = "user@example.com", ["authenticated"] = "true" }
                });
            }
            db.Events.AddRange(events);
            await db.SaveChangesAsync();
        }

        var services = new ServiceCollection();
        services.AddScoped<OrgContext>();
        services.AddScoped<IOrgContext>(sp => sp.GetRequiredService<OrgContext>());
        services.AddScoped(sp => new KellaDbContext(options, sp.GetRequiredService<IOrgContext>()));
        services.AddSingleton<IBaselineProvider, DbBaselineProvider>();
        var sp = services.BuildServiceProvider();
        var scopeFactory = sp.GetRequiredService<IServiceScopeFactory>();
        var baselineProvider = sp.GetRequiredService<IBaselineProvider>();

        var writer = new BaselineWriterService(scopeFactory, baselineProvider, NullLogger<BaselineWriterService>.Instance);
        await writer.ComputeBaselinesAsync(CancellationToken.None);

        using (var db = new KellaDbContext(options, orgContext))
        {
            var baselines = await db.Baselines.IgnoreQueryFilters().Where(b => b.OrganizationId == orgId).ToListAsync();
            Assert.NotEmpty(baselines);
            Assert.True(baselines.All(b => b.P95 > 0));
        }
    }

    [Fact]
    public async Task Startup_calls_PopulateFromDatabase_for_all_orgs()
    {
        var dbName = $"kella-startup-{Guid.NewGuid():N}";
        var options = new DbContextOptionsBuilder<KellaDbContext>()
            .UseInMemoryDatabase(dbName)
            .Options;

        var org1 = new Organization { Id = Guid.NewGuid(), Name = "Org 1" };
        var org2 = new Organization { Id = Guid.NewGuid(), Name = "Org 2" };

        var orgContext = new OrgContext();
        using (var db = new KellaDbContext(options, orgContext))
        {
            db.Organizations.AddRange(org1, org2);
            db.Baselines.Add(new Baseline
            {
                OrganizationId = org1.Id,
                EntityKind = "mailbox",
                EntityId = "srv1:user1@org1.com",
                HourOfWeek = 10,
                P95 = 42.0
            });
            db.Baselines.Add(new Baseline
            {
                OrganizationId = org2.Id,
                EntityKind = "mailbox",
                EntityId = "srv2:user2@org2.com",
                HourOfWeek = 10,
                P95 = 99.0
            });
            await db.SaveChangesAsync();
        }

        var services = new ServiceCollection();
        services.AddScoped<OrgContext>();
        services.AddScoped<IOrgContext>(sp => sp.GetRequiredService<OrgContext>());
        services.AddScoped(sp => new KellaDbContext(options, sp.GetRequiredService<IOrgContext>()));
        services.AddSingleton<IBaselineProvider, DbBaselineProvider>();
        var sp = services.BuildServiceProvider();
        var scopeFactory = sp.GetRequiredService<IServiceScopeFactory>();
        var baselineProvider = sp.GetRequiredService<IBaselineProvider>();

        var writer = new BaselineWriterService(scopeFactory, baselineProvider, NullLogger<BaselineWriterService>.Instance);

        await writer.StartAsync(CancellationToken.None);
        await Task.Delay(100);
        await writer.StopAsync(CancellationToken.None);

        Assert.Equal(42.0, baselineProvider.GetP95(org1.Id, "mailbox", "srv1:user1@org1.com", 10));
        Assert.Equal(99.0, baselineProvider.GetP95(org2.Id, "mailbox", "srv2:user2@org2.com", 10));
    }

    [Fact]
    public async Task Buckets_that_triggered_outbound_spike_incident_are_excluded()
    {
        var dbName = $"kella-spike-exclude-{Guid.NewGuid():N}";
        var options = new DbContextOptionsBuilder<KellaDbContext>()
            .UseInMemoryDatabase(dbName)
            .Options;

        var orgId = Guid.NewGuid();
        var serverId = Guid.NewGuid();
        var orgContext = new OrgContext();

        var now = DateTimeOffset.UtcNow;
        var sender = "spiker@example.com";
        var entityKey = $"{serverId}:{sender}";
        var spikeBucketTime = now.AddHours(-5);

        using (var db = new KellaDbContext(options, orgContext))
        {
            db.Organizations.Add(new Organization { Id = orgId, Name = "Org Spike" });
            db.Servers.Add(new Server { Id = serverId, OrganizationId = orgId, Name = "srv-1" });

            // 26 hours of data: 2 messages per 10-minute bucket
            for (int h = 0; h < 26; h++)
            {
                var baseHour = now.AddHours(-26 + h);
                for (int m = 0; m < 6; m++)
                {
                    var bucketTime = baseHour.AddMinutes(m * 10);
                    for (int k = 0; k < 2; k++)
                    {
                        db.Events.Add(new KellaEvent
                        {
                            Id = Guid.CreateVersion7(),
                            OrganizationId = orgId,
                            ServerId = serverId,
                            Ts = bucketTime.AddSeconds(k * 10),
                            Module = Modules.Mail,
                            Type = EventTypes.MailMessageQueued,
                            Attrs = new() { ["sender"] = sender, ["authenticated"] = "true" }
                        });
                    }
                }
            }

            // In hour -5, bucket 0: add 500 spike messages
            for (int k = 0; k < 500; k++)
            {
                db.Events.Add(new KellaEvent
                {
                    Id = Guid.CreateVersion7(),
                    OrganizationId = orgId,
                    ServerId = serverId,
                    Ts = spikeBucketTime.AddSeconds(k),
                    Module = Modules.Mail,
                    Type = EventTypes.MailMessageQueued,
                    Attrs = new() { ["sender"] = sender, ["authenticated"] = "true" }
                });
            }

            // Create an incident and finding for this outbound_spike
            var incident = new Incident
            {
                Id = Guid.NewGuid(),
                OrganizationId = orgId,
                ServerId = serverId,
                Type = "mail",
                Severity = Severity.Critical,
                Title = "Outbound spike incident"
            };
            db.Incidents.Add(incident);

            db.Findings.Add(new Finding
            {
                OrganizationId = orgId,
                ServerId = serverId,
                IncidentId = incident.Id,
                RuleCode = "mail.outbound_spike",
                Title = "Outbound spike",
                FirstSeen = spikeBucketTime,
                LastSeen = spikeBucketTime.AddMinutes(9),
                Evidence = new() { ["sender"] = sender }
            });

            await db.SaveChangesAsync();
        }

        var services = new ServiceCollection();
        services.AddScoped<OrgContext>();
        services.AddScoped<IOrgContext>(sp => sp.GetRequiredService<OrgContext>());
        services.AddScoped(sp => new KellaDbContext(options, sp.GetRequiredService<IOrgContext>()));
        services.AddSingleton<IBaselineProvider, DbBaselineProvider>();
        var sp = services.BuildServiceProvider();
        var scopeFactory = sp.GetRequiredService<IServiceScopeFactory>();
        var baselineProvider = sp.GetRequiredService<IBaselineProvider>();

        var writer = new BaselineWriterService(scopeFactory, baselineProvider, NullLogger<BaselineWriterService>.Instance);
        await writer.ComputeBaselinesAsync(CancellationToken.None);

        // Check hour of week for spikeBucketTime
        var utc = spikeBucketTime.UtcDateTime;
        int dayIndex = ((int)utc.DayOfWeek + 6) % 7;
        int spikeHourOfWeek = (dayIndex * 24) + utc.Hour;

        using (var db = new KellaDbContext(options, orgContext))
        {
            var baseline = await db.Baselines
                .IgnoreQueryFilters()
                .FirstOrDefaultAsync(b => b.OrganizationId == orgId && b.EntityId == entityKey && b.HourOfWeek == spikeHourOfWeek);

            Assert.NotNull(baseline);
            // If the 500 spike messages bucket was excluded, P95 must be 2.0 (normal rate), NOT >= 500!
            Assert.Equal(2.0, baseline.P95);
        }
    }
}
