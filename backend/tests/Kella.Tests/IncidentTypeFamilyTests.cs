using System.Net;
using System.Net.Http.Json;
using Kella.Api.Endpoints;
using Kella.Core.Domain;
using Kella.Infrastructure.Data;
using Kella.Infrastructure.Pipeline;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Kella.Tests;

public class IncidentTypeFamilyTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;

    public IncidentTypeFamilyTests(WebApplicationFactory<Program> factory)
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
    public async Task ServerHealthMonitor_recognizes_open_incident_with_family_type_server()
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<KellaDbContext>();

        var org = new Organization { Name = "Health Mon Org" };
        db.Organizations.Add(org);
        var server = new Server
        {
            OrganizationId = org.Id,
            Name = "srv-down-test",
            Status = ServerStatus.Online,
            LastSeenAt = DateTimeOffset.UtcNow.AddMinutes(-10) // Stale cutoff is 3 mins
        };
        db.Servers.Add(server);

        // Pre-existing incident with family "server"
        var existingIncident = new Incident
        {
            OrganizationId = org.Id,
            ServerId = server.Id,
            Number = 5001,
            Type = "server",
            Severity = Severity.Down,
            Title = "Server down",
            OpenedAt = DateTimeOffset.UtcNow.AddMinutes(-5),
            Status = IncidentStatus.Open
        };
        db.Incidents.Add(existingIncident);
        await db.SaveChangesAsync();

        var monitor = scope.ServiceProvider.GetRequiredService<ServerHealthMonitor>();
        await monitor.CheckOnceAsync(default);

        // Must NOT create a duplicate incident because an open "server" incident already exists
        var incidents = await db.Incidents.IgnoreQueryFilters()
            .Where(i => i.ServerId == server.Id && i.Status != IncidentStatus.Resolved)
            .ToListAsync();

        Assert.Single(incidents);
    }

    [Fact]
    public async Task IpReputationService_resolves_open_or_contained_incident_with_family_type_mail()
    {
        var mockDns = new MockDnsResolver();
        mockDns.ResolveHandler = _ => []; // Not listed

        using var factory = _factory.WithWebHostBuilder(b =>
        {
            b.ConfigureServices(services =>
            {
                services.AddSingleton<IDnsResolver>(mockDns);
            });
        });

        Guid orgId;
        Guid serverId;
        Guid mailIncId;

        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<KellaDbContext>();
            var org = new Organization { Name = "IP Rep Org" };
            db.Organizations.Add(org);
            var server = new Server
            {
                OrganizationId = org.Id,
                Name = "srv-iprep-test",
                PublicIp = "192.0.2.100",
                Status = ServerStatus.Online,
                LastSeenAt = DateTimeOffset.UtcNow
            };
            db.Servers.Add(server);

            // Incident created with family "mail"
            var mailIncident = new Incident
            {
                OrganizationId = org.Id,
                ServerId = server.Id,
                Number = 5002,
                Type = "mail",
                Severity = Severity.Warning,
                Title = "Sending IP listed",
                OpenedAt = DateTimeOffset.UtcNow.AddMinutes(-30),
                Status = IncidentStatus.Contained
            };
            db.Incidents.Add(mailIncident);

            // Pre-existing listed state
            var rep = new IpReputation
            {
                OrganizationId = org.Id,
                ServerId = server.Id,
                Ip = "192.0.2.100",
                Listed = true,
                ReturnCode = "127.0.0.2",
                ListedSince = DateTimeOffset.UtcNow.AddHours(-1),
                LastChecked = DateTimeOffset.UtcNow.AddMinutes(-15)
            };
            db.IpReputations.Add(rep);
            await db.SaveChangesAsync();

            orgId = org.Id;
            serverId = server.Id;
            mailIncId = mailIncident.Id;
        }

        using (var scope = factory.Services.CreateScope())
        {
            var ipRepService = scope.ServiceProvider.GetRequiredService<IpReputationService>();
            await ipRepService.CheckReputationAsync(default);

            var db = scope.ServiceProvider.GetRequiredService<KellaDbContext>();
            var refreshed = await db.Incidents.IgnoreQueryFilters().FirstAsync(i => i.Id == mailIncId);
            Assert.Equal(IncidentStatus.Resolved, refreshed.Status);
        }
    }

    [Fact]
    public async Task DashboardEndpoints_filtering_incidents_by_type_matches_both_family_and_rule_code()
    {
        Guid demoOrgId;
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<KellaDbContext>();
            var demoOrg = await db.Organizations.IgnoreQueryFilters().FirstAsync();
            demoOrgId = demoOrg.Id;

            var inc1 = new Incident
            {
                OrganizationId = demoOrgId,
                Number = 6001,
                Type = "mail",
                Severity = Severity.Warning,
                Title = "Mail incident family",
                OpenedAt = DateTimeOffset.UtcNow.AddMinutes(-10),
                Status = IncidentStatus.Open
            };
            var inc2 = new Incident
            {
                OrganizationId = demoOrgId,
                Number = 6002,
                Type = "mail.outbound_spike",
                Severity = Severity.Critical,
                Title = "Mail incident rule code",
                OpenedAt = DateTimeOffset.UtcNow.AddMinutes(-5),
                Status = IncidentStatus.Open
            };
            var inc3 = new Incident
            {
                OrganizationId = demoOrgId,
                Number = 6003,
                Type = "ssh",
                Severity = Severity.Warning,
                Title = "SSH incident",
                OpenedAt = DateTimeOffset.UtcNow.AddMinutes(-2),
                Status = IncidentStatus.Open
            };
            db.Incidents.AddRange(inc1, inc2, inc3);
            await db.SaveChangesAsync();
        }

        var client = _factory.CreateClient();

        // Query with family "mail" -> should match inc1 ("mail") and inc2 ("mail.outbound_spike")
        var mailRes = await client.GetFromJsonAsync<List<IncidentListItem>>($"/api/incidents?type=mail");
        Assert.NotNull(mailRes);
        Assert.True(mailRes.Count >= 2);
        Assert.Contains(mailRes, i => i.Number == "INC-6001");
        Assert.Contains(mailRes, i => i.Number == "INC-6002");
        Assert.DoesNotContain(mailRes, i => i.Number == "INC-6003");

        // Query with rule code "mail.outbound_spike" -> should match both family "mail" and rule code "mail.outbound_spike"
        var spikeRes = await client.GetFromJsonAsync<List<IncidentListItem>>($"/api/incidents?type=mail.outbound_spike");
        Assert.NotNull(spikeRes);
        Assert.True(spikeRes.Count >= 2);
        Assert.Contains(spikeRes, i => i.Number == "INC-6001");
        Assert.Contains(spikeRes, i => i.Number == "INC-6002");
        Assert.DoesNotContain(spikeRes, i => i.Number == "INC-6003");
    }
}
