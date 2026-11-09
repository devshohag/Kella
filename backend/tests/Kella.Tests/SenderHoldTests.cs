using System.Net;
using System.Net.Http.Json;
using Kella.Core;
using Kella.Core.Actions;
using Kella.Core.Domain;
using Kella.Core.Events;
using Kella.Core.Rules;
using Kella.Infrastructure;
using Kella.Infrastructure.Data;
using Kella.Infrastructure.Pipeline;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Kella.Tests;

public class SenderHoldTests(WebApplicationFactory<Program> factory) : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory = factory.WithWebHostBuilder(b =>
    {
        b.UseEnvironment("Development");
        b.UseSetting("ConnectionStrings:Postgres", "");
        b.UseSetting("Kella:RunPipelineInApi", "true");
        b.UseSetting("Kella:Jwt:Key", "kella-testing-only-signing-key-32b");
        b.UseSetting("Kella:Seed:OwnerPassword", "test-owner-password");
        b.UseSetting("Kella:Commands:PrivateKey", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
    });

    private static KellaEvent SpikeEvent(Guid orgId, Guid serverId, string sender, DateTimeOffset ts) => new()
    {
        OrganizationId = orgId,
        ServerId = serverId,
        Ts = ts,
        Module = Modules.Mail,
        Type = EventTypes.MailMessageQueued,
        Attrs = new() { ["sender"] = sender, ["authenticated"] = "true" },
    };

    [Fact]
    public void Hold_action_carries_default_ttl()
    {
        var rule = new MailOutboundSpikeRule(minSpikeCount: 1);
        var match = rule.Evaluate(SpikeEvent(Guid.NewGuid(), Guid.NewGuid(), "sender@example.com", DateTimeOffset.UtcNow));

        Assert.NotNull(match);
        var action = Assert.Single(match.Actions);
        Assert.Equal("14400", action.Params["ttlSec"]);
    }

    [Fact]
    public void Hold_ttl_is_configurable()
    {
        var rule = new MailOutboundSpikeRule(minSpikeCount: 1, holdTtlSeconds: 7200);
        var match = rule.Evaluate(SpikeEvent(Guid.NewGuid(), Guid.NewGuid(), "configured@example.com", DateTimeOffset.UtcNow));

        Assert.NotNull(match);
        Assert.Equal("7200", Assert.Single(match.Actions).Params["ttlSec"]);
    }

    [Fact]
    public async Task Expired_hold_queues_release_but_fresh_hold_does_not()
    {
        Guid expiredId;
        Guid freshId;

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<KellaDbContext>();
            var org = await db.Organizations.IgnoreQueryFilters().FirstAsync();
            scope.ServiceProvider.GetRequiredService<OrgContext>().Set(org.Id);
            var server = new Server { OrganizationId = org.Id, Name = "ttl-srv", Status = ServerStatus.Online };
            db.Servers.Add(server);
            var incident = new Incident
            {
                OrganizationId = org.Id,
                Number = 9103,
                ServerId = server.Id,
                Type = "mail",
                Severity = Severity.Critical,
                Title = "TTL spike",
            };
            db.Incidents.Add(incident);
            var expired = new KellaAction
            {
                OrganizationId = org.Id,
                IncidentId = incident.Id,
                ServerId = server.Id,
                Kind = ActionKinds.HoldSender,
                Params = new() { ["sender"] = "expired@example.com", ["ttlSec"] = "60" },
                Mode = ActionMode.Auto,
                Status = ActionStatus.Succeeded,
                ExecutedAt = DateTimeOffset.UtcNow.AddMinutes(-5),
            };
            var fresh = new KellaAction
            {
                OrganizationId = org.Id,
                IncidentId = incident.Id,
                ServerId = server.Id,
                Kind = ActionKinds.HoldSender,
                Params = new() { ["sender"] = "fresh@example.com", ["ttlSec"] = "14400" },
                Mode = ActionMode.Auto,
                Status = ActionStatus.Succeeded,
                ExecutedAt = DateTimeOffset.UtcNow,
            };
            db.Actions.AddRange(expired, fresh);
            await db.SaveChangesAsync();
            expiredId = expired.Id;
            freshId = fresh.Id;
        }

        using (var scope = _factory.Services.CreateScope())
        {
            var service = scope.ServiceProvider.GetRequiredService<HoldExpiryService>();
            await service.CheckOnceAsync();
        }

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<KellaDbContext>();
            var releases = await db.Actions.IgnoreQueryFilters()
                .Where(a => a.Kind == ActionKinds.ReleaseSender)
                .ToListAsync();
            Assert.Contains(releases, r => r.Params["sender"] == "expired@example.com");
            Assert.DoesNotContain(releases, r => r.Params["sender"] == "fresh@example.com");
            Assert.NotEqual(Guid.Empty, expiredId);
            Assert.NotEqual(Guid.Empty, freshId);
        }
    }

    [Fact]
    public async Task Dashboard_release_endpoint_queues_signed_release_action_and_audit()
    {
        Guid holdId;
        Guid orgId;

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<KellaDbContext>();
            var org = await db.Organizations.IgnoreQueryFilters().FirstAsync();
            scope.ServiceProvider.GetRequiredService<OrgContext>().Set(org.Id);
            var server = new Server { OrganizationId = org.Id, Name = "release-srv", Status = ServerStatus.Online };
            db.Servers.Add(server);
            var incident = new Incident
            {
                OrganizationId = org.Id,
                Number = 9101,
                ServerId = server.Id,
                Type = "mail",
                Severity = Severity.Critical,
                Title = "Spike",
            };
            db.Incidents.Add(incident);
            var hold = new KellaAction
            {
                OrganizationId = org.Id,
                IncidentId = incident.Id,
                ServerId = server.Id,
                Kind = ActionKinds.HoldSender,
                Params = new() { ["sender"] = "held@example.com", ["ttlSec"] = "14400" },
                Mode = ActionMode.Auto,
                Status = ActionStatus.Succeeded,
                ExecutedAt = DateTimeOffset.UtcNow,
            };
            db.Actions.Add(hold);
            await db.SaveChangesAsync();
            holdId = hold.Id;
            orgId = org.Id;
        }

        var client = _factory.CreateClient();
        var res = await client.PostAsync($"/api/actions/{holdId}/release", null);

        Assert.Equal(HttpStatusCode.NoContent, res.StatusCode);

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<KellaDbContext>();
            scope.ServiceProvider.GetRequiredService<OrgContext>().Set(orgId);
            var release = await db.Actions.AsNoTracking()
                .FirstOrDefaultAsync(a => a.Kind == ActionKinds.ReleaseSender && a.OrganizationId == orgId);
            Assert.NotNull(release);
            Assert.Equal("held@example.com", release.Params["sender"]);
            var command = await db.AgentCommands.AsNoTracking()
                .FirstOrDefaultAsync(c => c.ActionId == release.Id);
            Assert.NotNull(command);
            Assert.False(string.IsNullOrWhiteSpace(command.Signature));
            var audit = await db.AuditLog.AsNoTracking()
                .FirstOrDefaultAsync(a => a.OrganizationId == orgId && a.Target == $"action:{release.Id}");
            Assert.NotNull(audit);
        }
    }

    [Fact]
    public async Task Telegram_release_reply_queues_release_sender()
    {
        Guid orgId;
        Guid incidentId;
        string alertText;

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<KellaDbContext>();
            var org = await db.Organizations.IgnoreQueryFilters().FirstAsync();
            scope.ServiceProvider.GetRequiredService<OrgContext>().Set(org.Id);

            db.Users.Add(new User
            {
                OrganizationId = org.Id,
                Email = "release-responder@example.com",
                Name = "Release Responder",
                Role = UserRole.Responder,
                TelegramChatId = "910001",
            });
            var server = new Server { OrganizationId = org.Id, Name = "tg-release-srv", Status = ServerStatus.Online };
            db.Servers.Add(server);
            var incident = new Incident
            {
                OrganizationId = org.Id,
                Number = 9102,
                ServerId = server.Id,
                Type = "mail",
                Severity = Severity.Critical,
                Title = "Spike release",
                Summary = "Spike release body",
            };
            db.Incidents.Add(incident);
            db.Actions.Add(new KellaAction
            {
                OrganizationId = org.Id,
                IncidentId = incident.Id,
                ServerId = server.Id,
                Kind = ActionKinds.HoldSender,
                Params = new() { ["sender"] = "tg-held@example.com", ["ttlSec"] = "14400" },
                Mode = ActionMode.Auto,
                Status = ActionStatus.Succeeded,
                ExecutedAt = DateTimeOffset.UtcNow,
            });
            await db.SaveChangesAsync();
            orgId = org.Id;
            incidentId = incident.Id;
            alertText = Infrastructure.Alerting.TelegramAlertChannel.Format(
                new AlertMessage(incident.Id, incident.Number, Severity.Critical, incident.Title, incident.Summary, []));
        }

        var client = _factory.CreateClient();
        var payload = new
        {
            update_id = 991001L,
            message = new
            {
                chat = new { id = "910001" },
                text = "release",
                reply_to_message = new { text = alertText },
            },
        };
        var res = await client.PostAsJsonAsync("/api/hooks/telegram", payload);
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<KellaDbContext>();
            var release = await db.Actions.IgnoreQueryFilters()
                .FirstOrDefaultAsync(a => a.OrganizationId == orgId && a.Kind == ActionKinds.ReleaseSender);
            Assert.NotNull(release);
            Assert.Equal(incidentId, release.IncidentId);
            Assert.Equal("tg-held@example.com", release.Params["sender"]);
        }
    }
}
