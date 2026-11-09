using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Kella.Api;
using Kella.Core;
using Kella.Core.Domain;
using Kella.Core.Events;
using Kella.Core.Rules;
using Kella.Infrastructure.Data;
using Kella.Infrastructure.Pipeline;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Kella.Tests;

public class BaselineTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;

    public BaselineTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory.WithWebHostBuilder(b =>
        {
            b.UseEnvironment("Development");
            b.UseSetting("ConnectionStrings:Postgres", "");
            b.UseSetting("Kella:RunPipelineInApi", "true");
            b.UseSetting("Kella:Jwt:Key", "kella-testing-only-signing-key-32b");
            b.UseSetting("Kella:Seed:OwnerPassword", "test-owner-password");
            b.UseSetting("Kella:Commands:PrivateKey", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
        });
    }

    [Fact]
    public void HourOfWeek_is_computed_in_UTC_for_non_UTC_offset()
    {
        var orgId = Guid.NewGuid();
        var serverId = Guid.NewGuid();
        var baselines = new InMemoryBaselineProvider();

        // 2026-11-09T03:30:00+05:00 is 2026-11-08T22:30:00Z (Sunday 22:30 UTC).
        // In UTC (Monday=0 ... Sunday=6), Sunday 22:00 is (6 * 24) + 22 = 166.
        int expectedUtcHourOfWeek = (6 * 24) + 22; // 166

        // Set baseline for expected UTC hour of week for mailbox entityId "{serverId}:user@example.com"
        baselines.SetBaseline(orgId, "mailbox", $"{serverId}:user@example.com", expectedUtcHourOfWeek, 5.0);

        var rule = new MailOutboundSpikeRule(minSpikeCount: 10, baselines: baselines);

        // Send 15 messages (15 > minSpikeCount 10).
        // Since baseline exists (p95=5.0, 20x p95 = 100), 15 messages is NOT a spike (15 <= 100).
        var nonUtcTs = DateTimeOffset.Parse("2026-11-09T03:30:00+05:00");
        var matches = new List<RuleMatch>();
        for (int i = 0; i < 15; i++)
        {
            var evt = new KellaEvent
            {
                OrganizationId = orgId,
                ServerId = serverId,
                Ts = nonUtcTs.AddSeconds(i),
                Module = Modules.Mail,
                Type = EventTypes.MailMessageQueued,
                Attrs = new() { ["sender"] = "user@example.com", ["authenticated"] = "true" }
            };
            var m = rule.Evaluate(evt);
            if (m != null) matches.Add(m);
        }

        // Must be empty because 15 is well below 20x p95 (100).
        Assert.Empty(matches);
    }

    [Fact]
    public void Rule_uses_20x_p95_when_baseline_exists_and_fixed_threshold_when_not()
    {
        var orgId = Guid.NewGuid();
        var serverId = Guid.NewGuid();
        var baselines = new InMemoryBaselineProvider();
        var t0 = DateTimeOffset.UtcNow;
        var utc = t0.UtcDateTime;
        int dayIndex = ((int)utc.DayOfWeek + 6) % 7;
        int hourOfWeek = (dayIndex * 24) + utc.Hour;

        // Baseline exists for sender1: p95 = 5.0 -> 20x = 100.
        baselines.SetBaseline(orgId, "mailbox", $"{serverId}:sender1@example.com", hourOfWeek, 5.0);

        var rule = new MailOutboundSpikeRule(minSpikeCount: 50, baselines: baselines);

        // Test Sender 1 (has baseline):
        // 60 messages: > fixed minSpikeCount (50), but < 20x p95 (100) -> NO SPIKE
        var sender1Matches = new List<RuleMatch>();
        for (int i = 0; i < 60; i++)
        {
            var evt = new KellaEvent
            {
                OrganizationId = orgId,
                ServerId = serverId,
                Ts = t0.AddSeconds(i),
                Module = Modules.Mail,
                Type = EventTypes.MailMessageQueued,
                Attrs = new() { ["sender"] = "sender1@example.com", ["authenticated"] = "true" }
            };
            var m = rule.Evaluate(evt);
            if (m != null) sender1Matches.Add(m);
        }
        Assert.Empty(sender1Matches);

        // Continue Sender 1 to 105 messages: > 20x p95 (100) -> SPIKE!
        for (int i = 60; i < 105; i++)
        {
            var evt = new KellaEvent
            {
                OrganizationId = orgId,
                ServerId = serverId,
                Ts = t0.AddSeconds(i),
                Module = Modules.Mail,
                Type = EventTypes.MailMessageQueued,
                Attrs = new() { ["sender"] = "sender1@example.com", ["authenticated"] = "true" }
            };
            var m = rule.Evaluate(evt);
            if (m != null) sender1Matches.Add(m);
        }
        Assert.NotEmpty(sender1Matches);

        // Test Sender 2 (NO baseline):
        // Fixed threshold = 50. 49 messages -> NO SPIKE
        var sender2Matches = new List<RuleMatch>();
        for (int i = 0; i < 49; i++)
        {
            var evt = new KellaEvent
            {
                OrganizationId = orgId,
                ServerId = serverId,
                Ts = t0.AddSeconds(i),
                Module = Modules.Mail,
                Type = EventTypes.MailMessageQueued,
                Attrs = new() { ["sender"] = "sender2@example.com", ["authenticated"] = "true" }
            };
            var m = rule.Evaluate(evt);
            if (m != null) sender2Matches.Add(m);
        }
        Assert.Empty(sender2Matches);

        // 50th message -> SPIKE (fixed threshold met)
        var evt50 = new KellaEvent
        {
            OrganizationId = orgId,
            ServerId = serverId,
            Ts = t0.AddSeconds(50),
            Module = Modules.Mail,
            Type = EventTypes.MailMessageQueued,
            Attrs = new() { ["sender"] = "sender2@example.com", ["authenticated"] = "true" }
        };
        var matchSender2At50 = rule.Evaluate(evt50);
        Assert.NotNull(matchSender2At50);
    }

    [Fact]
    public async Task BaselineWriterService_computes_p95_only_when_24h_data_exist()
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<KellaDbContext>();
        var writer = scope.ServiceProvider.GetRequiredService<BaselineWriterService>();
        var baselineProvider = scope.ServiceProvider.GetRequiredService<IBaselineProvider>();

        var org = new Organization { Name = "Org Baseline Test" };
        db.Organizations.Add(org);
        var server = new Server { OrganizationId = org.Id, Name = "srv-base" };
        db.Servers.Add(server);

        var now = DateTimeOffset.UtcNow;

        // Sender 1: Events spanning 26 hours (> 24h)
        for (int h = 0; h < 26; h++)
        {
            var eventTs = now.AddHours(-26 + h);
            // 6 messages in the hour
            for (int m = 0; m < 6; m++)
            {
                db.Events.Add(new KellaEvent
                {
                    OrganizationId = org.Id,
                    ServerId = server.Id,
                    Ts = eventTs.AddMinutes(m * 10),
                    Module = Modules.Mail,
                    Type = EventTypes.MailMessageQueued,
                    Attrs = new() { ["sender"] = "sender24h@test.org", ["authenticated"] = "true" }
                });
            }
        }

        // Sender 2: Events spanning only 5 hours (< 24h)
        for (int h = 0; h < 5; h++)
        {
            var eventTs = now.AddHours(-5 + h);
            for (int m = 0; m < 6; m++)
            {
                db.Events.Add(new KellaEvent
                {
                    OrganizationId = org.Id,
                    ServerId = server.Id,
                    Ts = eventTs.AddMinutes(m * 10),
                    Module = Modules.Mail,
                    Type = EventTypes.MailMessageQueued,
                    Attrs = new() { ["sender"] = "sender5h@test.org", ["authenticated"] = "true" }
                });
            }
        }

        await db.SaveChangesAsync();

        // Run baseline writer once
        await writer.ComputeBaselinesAsync();

        // Check rows in database
        var sender24hKey = $"{server.Id}:sender24h@test.org";
        var sender5hKey = $"{server.Id}:sender5h@test.org";

        var baselineRows24h = await db.Baselines
            .IgnoreQueryFilters()
            .Where(b => b.OrganizationId == org.Id && b.EntityId == sender24hKey)
            .ToListAsync();

        var baselineRows5h = await db.Baselines
            .IgnoreQueryFilters()
            .Where(b => b.OrganizationId == org.Id && b.EntityId == sender5hKey)
            .ToListAsync();

        // Sender with > 24h MUST have baseline rows
        Assert.NotEmpty(baselineRows24h);
        Assert.True(baselineRows24h.All(b => b.P95 > 0));

        // Sender with < 24h MUST NOT have baseline rows ("until 24 h of data exist -> no baseline row")
        Assert.Empty(baselineRows5h);

        // Verify baselineProvider cache was updated and returns p95
        var firstRow = baselineRows24h.First();
        var cachedP95 = baselineProvider.GetP95(org.Id, "mailbox", sender24hKey, firstRow.HourOfWeek);
        Assert.NotNull(cachedP95);
        Assert.Equal(firstRow.P95, cachedP95.Value);
    }
}
