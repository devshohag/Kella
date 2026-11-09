using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Hosting;
using Kella.Core;
using Kella.Core.Actions;
using Kella.Core.Domain;
using Kella.Core.Events;
using Kella.Infrastructure.Data;
using Kella.Infrastructure.Pipeline;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Kella.Tests;

public class AutoActionLifecycleTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;

    public AutoActionLifecycleTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory.WithWebHostBuilder(b =>
        {
            b.UseEnvironment("Development");
            b.UseSetting("ConnectionStrings:Postgres", "");
            b.UseSetting("Kella:RunPipelineInApi", "true");
            b.UseSetting("Kella:Jwt:Key", "kella-testing-only-signing-key-32b");
            b.UseSetting("Kella:Seed:OwnerPassword", "test-owner-password");
        });
    }

    [Fact]
    public async Task Same_ip_blocked_after_ttl_elapsed_creates_new_block_action()
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<KellaDbContext>();
        var service = scope.ServiceProvider.GetRequiredService<RuleEngineService>();

        var org = new Organization { Name = "TTL Org" };
        db.Organizations.Add(org);
        var server = new Server { OrganizationId = org.Id, Name = "srv-ttl" };
        db.Servers.Add(server);
        await db.SaveChangesAsync();

        var t0 = DateTimeOffset.UtcNow;
        var attackerIp = "198.51.100.99";

        // Initial block_ip created 10 minutes ago with 300s TTL (5 min TTL)
        var oldAction = new KellaAction
        {
            OrganizationId = org.Id,
            ServerId = server.Id,
            Kind = ActionKinds.BlockIp,
            Params = new() { ["ip"] = attackerIp, ["ttlSec"] = "300" },
            Mode = ActionMode.Auto,
            Status = ActionStatus.Succeeded,
            CreatedAt = t0.AddMinutes(-10),
            ExpiresAt = null, // Old code left this null
        };
        db.Actions.Add(oldAction);
        await db.SaveChangesAsync();

        // New match arrives now (TTL of 300s has elapsed 5 minutes ago)
        var match = new RuleMatch(
            "ssh.bruteforce",
            Severity.Warning,
            $"SSH brute-force from {attackerIp}",
            $"Failed logins from {attackerIp}",
            new Dictionary<string, string> { ["sourceIp"] = attackerIp },
            [
                new SuggestedAction(ActionKinds.BlockIp, new Dictionary<string, string> { ["ip"] = attackerIp, ["ttlSec"] = "300" }, ActionMode.Auto, $"Block {attackerIp}")
            ]);

        var evt = new KellaEvent
        {
            OrganizationId = org.Id,
            ServerId = server.Id,
            Ts = t0,
            Module = Modules.Server,
            Type = EventTypes.SshAuthFailed,
            Attrs = new() { ["source_ip"] = attackerIp }
        };

        await service.PersistMatchAsync(evt, match);

        var actions = await db.Actions.IgnoreQueryFilters()
            .Where(a => a.OrganizationId == org.Id && a.Kind == ActionKinds.BlockIp)
            .ToListAsync();

        // Must create a new block_ip action because TTL elapsed
        Assert.Equal(2, actions.Count);
    }

    [Fact]
    public async Task Hold_then_release_then_new_spike_creates_new_hold_action()
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<KellaDbContext>();
        var service = scope.ServiceProvider.GetRequiredService<RuleEngineService>();

        var org = new Organization { Name = "Hold Release Org" };
        db.Organizations.Add(org);
        var server = new Server { OrganizationId = org.Id, Name = "srv-hold-rel" };
        db.Servers.Add(server);
        await db.SaveChangesAsync();

        var t0 = DateTimeOffset.UtcNow;
        var sender = "user@testdomain.com";

        // 1. Initial spike fires and creates hold_sender
        var spikeMatch = new RuleMatch(
            "mail.outbound_spike",
            Severity.Critical,
            $"Outbound spike from {sender}",
            "Spike",
            new Dictionary<string, string> { ["sender"] = sender },
            [
                new SuggestedAction(ActionKinds.HoldSender, new Dictionary<string, string> { ["sender"] = sender }, ActionMode.Auto, "Hold sender")
            ]);

        var spikeEvt = new KellaEvent
        {
            OrganizationId = org.Id,
            ServerId = server.Id,
            Ts = t0,
            Module = Modules.Mail,
            Type = EventTypes.MailMessageQueued,
            Attrs = new() { ["sender"] = sender, ["authenticated"] = "true" }
        };

        await service.PersistMatchAsync(spikeEvt, spikeMatch);

        var holdAction = await db.Actions.IgnoreQueryFilters()
            .FirstAsync(a => a.OrganizationId == org.Id && a.Kind == ActionKinds.HoldSender);
        holdAction.Status = ActionStatus.Succeeded;
        await db.SaveChangesAsync();

        // 2. Release sender action executes and succeeds
        var releaseAction = new KellaAction
        {
            OrganizationId = org.Id,
            ServerId = server.Id,
            Kind = ActionKinds.ReleaseSender,
            Params = new() { ["sender"] = sender },
            Mode = ActionMode.Approval,
            Status = ActionStatus.Queued,
        };
        db.Actions.Add(releaseAction);
        await db.SaveChangesAsync();

        // Simulate release command success
        await ActionLifecycleHelper.MarkActionSucceededAsync(db, releaseAction);
        await db.SaveChangesAsync();

        // Prior hold action must now be marked Reverted
        var reloadedHold = await db.Actions.IgnoreQueryFilters().FirstAsync(a => a.Id == holdAction.Id);
        Assert.Equal(ActionStatus.Reverted, reloadedHold.Status);

        // 3. New spike arrives 15 minutes later
        var newSpikeEvt = new KellaEvent
        {
            OrganizationId = org.Id,
            ServerId = server.Id,
            Ts = t0.AddMinutes(15),
            Module = Modules.Mail,
            Type = EventTypes.MailMessageQueued,
            Attrs = new() { ["sender"] = sender, ["authenticated"] = "true" }
        };

        await service.PersistMatchAsync(newSpikeEvt, spikeMatch);

        var allHolds = await db.Actions.IgnoreQueryFilters()
            .Where(a => a.OrganizationId == org.Id && a.Kind == ActionKinds.HoldSender)
            .ToListAsync();

        // Must create a new hold action
        Assert.Equal(2, allHolds.Count);
        Assert.Contains(allHolds, a => a.Status == ActionStatus.Reverted);
        Assert.Contains(allHolds, a => a.Status == ActionStatus.Queued);
    }

    [Fact]
    public async Task Hold_within_window_is_still_deduplicated()
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<KellaDbContext>();
        var service = scope.ServiceProvider.GetRequiredService<RuleEngineService>();

        var org = new Organization { Name = "Dedupe Window Org" };
        db.Organizations.Add(org);
        var server = new Server { OrganizationId = org.Id, Name = "srv-window" };
        db.Servers.Add(server);
        await db.SaveChangesAsync();

        var t0 = DateTimeOffset.UtcNow;
        var sender = "spammer@testdomain.com";

        var spikeMatch = new RuleMatch(
            "mail.outbound_spike",
            Severity.Critical,
            $"Outbound spike from {sender}",
            "Spike",
            new Dictionary<string, string> { ["sender"] = sender },
            [
                new SuggestedAction(ActionKinds.HoldSender, new Dictionary<string, string> { ["sender"] = sender }, ActionMode.Auto, "Hold sender")
            ]);

        var spikeEvt1 = new KellaEvent
        {
            OrganizationId = org.Id,
            ServerId = server.Id,
            Ts = t0,
            Module = Modules.Mail,
            Type = EventTypes.MailMessageQueued,
            Attrs = new() { ["sender"] = sender, ["authenticated"] = "true" }
        };

        await service.PersistMatchAsync(spikeEvt1, spikeMatch);

        // 10 minutes later (within the 1-hour window)
        var spikeEvt2 = new KellaEvent
        {
            OrganizationId = org.Id,
            ServerId = server.Id,
            Ts = t0.AddMinutes(10),
            Module = Modules.Mail,
            Type = EventTypes.MailMessageQueued,
            Attrs = new() { ["sender"] = sender, ["authenticated"] = "true" }
        };

        await service.PersistMatchAsync(spikeEvt2, spikeMatch);

        var allHolds = await db.Actions.IgnoreQueryFilters()
            .Where(a => a.OrganizationId == org.Id && a.Kind == ActionKinds.HoldSender)
            .ToListAsync();

        // Must still be deduplicated to exactly 1 hold action
        Assert.Single(allHolds);
    }
}
