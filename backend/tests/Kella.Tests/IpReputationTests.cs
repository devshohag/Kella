using System;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Kella.Api;
using Kella.Core.Domain;
using Kella.Infrastructure.Data;
using Kella.Infrastructure.Pipeline;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;

namespace Kella.Tests;

public class IpReputationTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;

    public IpReputationTests(WebApplicationFactory<Program> factory)
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
    public async Task IpReputation_lifecycle_transitions_and_restart_idempotency()
    {
        var mockDns = new MockDnsResolver();
        mockDns.ResolveHandler = _ => [IPAddress.Parse("127.0.0.2")];

        using var factory = _factory.WithWebHostBuilder(b =>
        {
            b.ConfigureServices(services =>
            {
                services.AddSingleton<IDnsResolver>(mockDns);
            });
        });

        Guid orgId;
        Guid serverId;
        var publicIp = "198.51.100.25";

        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<KellaDbContext>();
            var org = new Organization { Name = "Reputation Org" };
            db.Organizations.Add(org);
            var server = new Server
            {
                OrganizationId = org.Id,
                Name = "srv-mail",
                PublicIp = publicIp,
                Status = ServerStatus.Online
            };
            db.Servers.Add(server);
            await db.SaveChangesAsync();

            orgId = org.Id;
            serverId = server.Id;
        }

        using (var scope = factory.Services.CreateScope())
        {
            var service = scope.ServiceProvider.GetRequiredService<IpReputationService>();

            // 1. First run lists -> one incident
            await service.CheckReputationAsync();

            var db = scope.ServiceProvider.GetRequiredService<KellaDbContext>();
            var incidents = await db.Incidents.IgnoreQueryFilters().Where(i => i.OrganizationId == orgId).ToListAsync();
            Assert.Single(incidents);
            Assert.Equal(IncidentStatus.Open, incidents[0].Status);

            var rep = await db.IpReputations.AsNoTracking().IgnoreQueryFilters().FirstAsync(r => r.OrganizationId == orgId && r.Ip == publicIp);
            Assert.True(rep.Listed);
            Assert.Equal("127.0.0.2", rep.ReturnCode);
            var firstChecked = rep.LastChecked;

            await Task.Delay(50);

            // 2. Second run -> no new incident and last_checked updated
            await service.CheckReputationAsync();

            incidents = await db.Incidents.AsNoTracking().IgnoreQueryFilters().Where(i => i.OrganizationId == orgId).ToListAsync();
            Assert.Single(incidents); // Still 1 incident

            var repSecond = await db.IpReputations.AsNoTracking().IgnoreQueryFilters().FirstAsync(r => r.OrganizationId == orgId && r.Ip == publicIp);
            Assert.True(repSecond.LastChecked > firstChecked);

            // 3. Resolve transition: DNS now returns empty (not listed) -> resolves incident
            mockDns.ResolveHandler = _ => Array.Empty<IPAddress>();
            await service.CheckReputationAsync();

            var repThird = await db.IpReputations.AsNoTracking().IgnoreQueryFilters().FirstAsync(r => r.OrganizationId == orgId && r.Ip == publicIp);
            Assert.False(repThird.Listed);

            var resolvedInc = await db.Incidents.AsNoTracking().IgnoreQueryFilters().FirstAsync(i => i.OrganizationId == orgId);
            Assert.Equal(IncidentStatus.Resolved, resolvedInc.Status);
            Assert.NotNull(resolvedInc.ResolvedAt);

            // 4. IP gets listed again -> opens new incident (total 2)
            mockDns.ResolveHandler = _ => [IPAddress.Parse("127.0.0.3")];
            await service.CheckReputationAsync();

            incidents = await db.Incidents.AsNoTracking().IgnoreQueryFilters().Where(i => i.OrganizationId == orgId).ToListAsync();
            Assert.Equal(2, incidents.Count);
        }

        // 5. Restart (new service instance with same DB) -> no duplicate incident!
        using (var scope = factory.Services.CreateScope())
        {
            var newServiceInstance = new IpReputationService(
                scope.ServiceProvider.GetRequiredService<IServiceScopeFactory>(),
                mockDns,
                scope.ServiceProvider.GetRequiredService<ILogger<IpReputationService>>());

            await newServiceInstance.CheckReputationAsync();

            var db = scope.ServiceProvider.GetRequiredService<KellaDbContext>();
            var incidents = await db.Incidents.IgnoreQueryFilters().Where(i => i.OrganizationId == orgId).ToListAsync();
            Assert.Equal(2, incidents.Count); // Still exactly 2 incidents!
        }
    }
}

public class MockDnsResolver : IDnsResolver
{
    public Func<string, IPAddress[]?>? ResolveHandler { get; set; }

    public Task<IPAddress[]?> ResolveAsync(string query, CancellationToken ct = default)
    {
        var result = ResolveHandler != null ? ResolveHandler(query) : Array.Empty<IPAddress>();
        return Task.FromResult(result);
    }
}
