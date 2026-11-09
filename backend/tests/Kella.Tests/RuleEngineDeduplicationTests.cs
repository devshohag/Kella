using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Kella.Api;
using Kella.Core;
using Kella.Core.Actions;
using Kella.Core.Domain;
using Kella.Core.Events;
using Kella.Infrastructure.Data;
using Kella.Infrastructure.Pipeline;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Kella.Tests;

public class RuleEngineDeduplicationTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;

    public RuleEngineDeduplicationTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory.WithWebHostBuilder(b =>
        {
            b.UseEnvironment("Testing");
            b.UseSetting("ConnectionStrings:Postgres", "");
            b.UseSetting("Kella:RunPipelineInApi", "true");
            b.UseSetting("Kella:Jwt:Key", "kella-testing-only-signing-key-32b");
            b.UseSetting("Kella:Seed:OwnerPassword", "test-owner-password");
            b.UseSetting("Kella:Commands:PrivateKey", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
        });
    }

    [Fact]
    public async Task Outbound_spike_followed_by_account_takeover_groups_into_one_incident_and_deduplicates_hold_sender()
    {
        var mockRouter = new MockAlertRouter();
        using var factory = _factory.WithWebHostBuilder(b =>
        {
            b.ConfigureServices(services =>
            {
                services.AddScoped<IAlertRouter>(_ => mockRouter);
            });
        });

        Guid orgId;
        Guid serverId;
        var sender = "compromised@corp.example";

        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<KellaDbContext>();
            var org = new Organization { Name = "Deduplication Org" };
            db.Organizations.Add(org);
            var server = new Server { OrganizationId = org.Id, Name = "srv-mail-dedup" };
            db.Servers.Add(server);
            await db.SaveChangesAsync();

            orgId = org.Id;
            serverId = server.Id;
        }

        using (var scope = factory.Services.CreateScope())
        {
            var service = scope.ServiceProvider.GetRequiredService<RuleEngineService>();
            var t0 = DateTimeOffset.UtcNow;

            // 1. Simulate outbound_spike match
            var spikeMatch = new RuleMatch(
                "mail.outbound_spike",
                Severity.Critical,
                $"Outbound email spike from {sender}",
                $"Spike detected for {sender}",
                new Dictionary<string, string> { ["sender"] = sender },
                [
                    new SuggestedAction(ActionKinds.HoldSender, new Dictionary<string, string> { ["sender"] = sender }, ActionMode.Auto, "Hold sender")
                ]);

            var spikeEvt = new KellaEvent
            {
                OrganizationId = orgId,
                ServerId = serverId,
                Ts = t0,
                Module = Modules.Mail,
                Type = EventTypes.MailMessageQueued,
                Attrs = new() { ["sender"] = sender }
            };

            await service.PersistMatchAsync(spikeEvt, spikeMatch);

            // 2. Simulate account_takeover match 30 minutes later (same sender, same server)
            var takeoverMatch = new RuleMatch(
                "mail.account_takeover",
                Severity.Critical,
                $"Likely account takeover: {sender}",
                $"Takeover detected for {sender}",
                new Dictionary<string, string> { ["sender"] = sender },
                [
                    new SuggestedAction(ActionKinds.HoldSender, new Dictionary<string, string> { ["sender"] = sender }, ActionMode.Auto, "Hold sender")
                ]);

            var takeoverEvt = new KellaEvent
            {
                OrganizationId = orgId,
                ServerId = serverId,
                Ts = t0.AddMinutes(30),
                Module = Modules.Mail,
                Type = EventTypes.MailMessageQueued,
                Attrs = new() { ["sender"] = sender }
            };

            await service.PersistMatchAsync(takeoverEvt, takeoverMatch);

            var db = scope.ServiceProvider.GetRequiredService<KellaDbContext>();
            var incidents = await db.Incidents.IgnoreQueryFilters().Where(i => i.OrganizationId == orgId).ToListAsync();
            var actions = await db.Actions.IgnoreQueryFilters().Where(a => a.OrganizationId == orgId && a.Kind == ActionKinds.HoldSender).ToListAsync();

            // (a) Must group into 1 incident
            Assert.Single(incidents);

            // (a) Must deduplicate: exactly 1 hold_sender action
            Assert.Single(actions);
        }
    }

    [Fact]
    public async Task Multiple_ssh_bruteforce_against_same_server_routes_only_one_initial_alert()
    {
        var mockRouter = new MockAlertRouter();
        using var factory = _factory.WithWebHostBuilder(b =>
        {
            b.ConfigureServices(services =>
            {
                services.AddScoped<IAlertRouter>(_ => mockRouter);
            });
        });

        Guid orgId;
        Guid serverId;

        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<KellaDbContext>();
            var org = new Organization { Name = "SSH Brute Org" };
            db.Organizations.Add(org);
            var server = new Server { OrganizationId = org.Id, Name = "srv-ssh-brute" };
            db.Servers.Add(server);
            await db.SaveChangesAsync();

            orgId = org.Id;
            serverId = server.Id;
        }

        using (var scope = factory.Services.CreateScope())
        {
            var service = scope.ServiceProvider.GetRequiredService<RuleEngineService>();
            var t0 = DateTimeOffset.UtcNow;

            // 10 ssh.bruteforce matches from different attacker IPs
            for (int i = 0; i < 10; i++)
            {
                var attackerIp = $"198.51.100.{i + 1}";
                var match = new RuleMatch(
                    "ssh.bruteforce",
                    Severity.Warning,
                    $"SSH brute-force from {attackerIp}",
                    $"Failed logins from {attackerIp}",
                    new Dictionary<string, string> { ["sourceIp"] = attackerIp },
                    [
                        new SuggestedAction(ActionKinds.BlockIp, new Dictionary<string, string> { ["ip"] = attackerIp }, ActionMode.Auto, $"Block {attackerIp}")
                    ]);

                var evt = new KellaEvent
                {
                    OrganizationId = orgId,
                    ServerId = serverId,
                    Ts = t0.AddMinutes(i),
                    Module = Modules.Server,
                    Type = EventTypes.SshAuthFailed,
                    Attrs = new() { ["source_ip"] = attackerIp }
                };

                await service.PersistMatchAsync(evt, match);
            }

            var db = scope.ServiceProvider.GetRequiredService<KellaDbContext>();
            var incidents = await db.Incidents.IgnoreQueryFilters().Where(i => i.OrganizationId == orgId).ToListAsync();

            // (b) Must group into 1 incident
            Assert.Single(incidents);

            // (b) Must route only 1 initial alert notification
            Assert.Single(mockRouter.RoutedIncidents);
        }
    }
}

public class MockAlertRouter : IAlertRouter
{
    public List<Incident> RoutedIncidents { get; } = new();

    public Task RouteAsync(Incident incident, CancellationToken ct = default)
    {
        RoutedIncidents.Add(incident);
        return Task.CompletedTask;
    }
}
