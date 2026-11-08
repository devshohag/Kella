using System.Net;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Kella.Core.Domain;
using Kella.Infrastructure.Data;

namespace Kella.Infrastructure.Pipeline;

/// <summary>
/// IP reputation checker (SPEC §17 Phase 2):
/// Performs DNSBL lookups periodically (e.g. zen.spamhaus.org, bl.spamcop.net)
/// for outbound sending IPs discovered from mail events or server public IPs.
/// </summary>
public sealed class IpReputationService(
    IServiceScopeFactory scopes,
    ILogger<IpReputationService> log) : BackgroundService
{
    private static readonly string[] DnsblZones =
    [
        "zen.spamhaus.org",
        "bl.spamcop.net"
    ];

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await CheckReputationAsync(ct);
            }
            catch (Exception ex)
            {
                log.LogError(ex, "DNSBL IP reputation check loop encountered an error");
            }

            // Wait 15 minutes before the next check (SPEC §17 Phase 2)
            await Task.Delay(TimeSpan.FromMinutes(15), ct);
        }
    }

    private async Task CheckReputationAsync(CancellationToken ct)
    {
        using var scope = scopes.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<KellaDbContext>();

        // Find servers with public IPs
        var servers = await db.Servers.IgnoreQueryFilters()
            .Where(s => s.Status == ServerStatus.Online && !string.IsNullOrEmpty(s.PublicIp))
            .ToListAsync(ct);

        foreach (var server in servers)
        {
            if (IPAddress.TryParse(server.PublicIp, out var ip) && ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                var isListed = await IsListedAsync(ip, ct);
                if (isListed)
                {
                    log.LogWarning("Server {ServerName} ({IP}) is listed on DNSBL!", server.Name, server.PublicIp);
                }
            }
        }
    }

    public static async Task<bool> IsListedAsync(IPAddress ip, CancellationToken ct = default)
    {
        var bytes = ip.GetAddressBytes();
        var reversed = $"{bytes[3]}.{bytes[2]}.{bytes[1]}.{bytes[0]}";

        foreach (var zone in DnsblZones)
        {
            var query = $"{reversed}.{zone}";
            try
            {
                var entry = await Dns.GetHostEntryAsync(query, ct);
                if (entry.AddressList.Length > 0)
                {
                    return true;
                }
            }
            catch
            {
                // NXDOMAIN or lookup failed -> not listed
            }
        }

        return false;
    }
}
