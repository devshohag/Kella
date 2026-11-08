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
/// Checks sending IPs from mail events and server public IPs periodically (every 15 min).
/// Per SPEC: treat only 127.0.0.2-127.0.0.11 as listed, ignore 127.255.255.x (log resolver refused),
/// and raise a finding/incident on new listing.
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

    // Cache tracked listings: key -> listedSince
    private readonly Dictionary<string, DateTimeOffset> _listedIps = new();

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

        // Collect distinct source IPs from recent mail events (last 24 hours)
        var since = DateTimeOffset.UtcNow.AddHours(-24);
        var mailIps = await db.Events.IgnoreQueryFilters()
            .Where(e => e.Module == "mail" && e.Ts >= since && e.SourceIp != null)
            .Select(e => new { e.OrganizationId, e.ServerId, SourceIp = e.SourceIp! })
            .Distinct()
            .Take(100)
            .ToListAsync(ct);

        // Also collect server public IPs
        var servers = await db.Servers.IgnoreQueryFilters()
            .Where(s => s.Status == ServerStatus.Online && !string.IsNullOrEmpty(s.PublicIp))
            .Select(s => new { s.OrganizationId, ServerId = s.Id, SourceIp = s.PublicIp! })
            .ToListAsync(ct);

        var targets = mailIps.Concat(servers).DistinctBy(x => x.SourceIp).ToList();

        foreach (var target in targets)
        {
            if (IPAddress.TryParse(target.SourceIp, out var ip) &&
                ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork &&
                !IPAddress.IsLoopback(ip))
            {
                var (isListed, listedIpResult) = await CheckDnsblAsync(ip, log, ct);
                var key = $"{target.OrganizationId}:{target.SourceIp}";

                if (isListed)
                {
                    var isNew = !_listedIps.ContainsKey(key);
                    var listedSince = isNew ? DateTimeOffset.UtcNow : _listedIps[key];
                    _listedIps[key] = listedSince;

                    if (isNew)
                    {
                        log.LogWarning("IP {IP} (Org {Org}) newly listed on DNSBL ({Result})!",
                            target.SourceIp, target.OrganizationId, listedIpResult);

                        // Persist finding and incident for newly listed sending IP
                        scope.ServiceProvider.GetRequiredService<OrgContext>().Set(target.OrganizationId);

                        var inc = new Incident
                        {
                            OrganizationId = target.OrganizationId,
                            Number = (db.Incidents.Max(i => (int?)i.Number) ?? 2000) + 1,
                            ServerId = target.ServerId,
                            Type = "mail.ip_reputation",
                            Severity = Severity.Warning,
                            Title = $"Sending IP {target.SourceIp} listed on DNSBL",
                            Summary = $"IP {target.SourceIp} returned {listedIpResult} on public DNSBL. Outbound deliverability impacted.",
                            OpenedAt = DateTimeOffset.UtcNow
                        };
                        db.Incidents.Add(inc);

                        db.Findings.Add(new Finding
                        {
                            OrganizationId = target.OrganizationId,
                            ServerId = target.ServerId,
                            RuleCode = "mail.ip_reputation",
                            Severity = Severity.Warning,
                            Title = $"DNSBL Blacklisted: {target.SourceIp}",
                            Summary = $"Listed on DNSBL with return code {listedIpResult}. First detected at {listedSince:u}.",
                            Evidence = new()
                            {
                                ["ip"] = target.SourceIp,
                                ["returnCode"] = listedIpResult ?? "",
                                ["listedSince"] = listedSince.ToString("O")
                            },
                            FirstSeen = listedSince,
                            LastSeen = DateTimeOffset.UtcNow,
                            IncidentId = inc.Id
                        });

                        await db.SaveChangesAsync(ct);
                    }
                }
                else
                {
                    _listedIps.Remove(key);
                }
            }
        }
    }

    public static async Task<(bool IsListed, string? ReturnCode)> CheckDnsblAsync(
        IPAddress ip, ILogger? logger, CancellationToken ct = default)
    {
        var bytes = ip.GetAddressBytes();
        var reversed = $"{bytes[3]}.{bytes[2]}.{bytes[1]}.{bytes[0]}";

        foreach (var zone in DnsblZones)
        {
            var query = $"{reversed}.{zone}";
            try
            {
                var entry = await Dns.GetHostEntryAsync(query, ct);
                foreach (var addr in entry.AddressList)
                {
                    var resBytes = addr.GetAddressBytes();
                    // Check for resolver rate-limit/refusal: 127.255.255.x
                    if (resBytes[0] == 127 && resBytes[1] == 255 && resBytes[2] == 255)
                    {
                        logger?.LogWarning("DNSBL zone {Zone} refused query or rate-limited: returned {Code}", zone, addr);
                        continue;
                    }

                    // SPEC: treat only 127.0.0.2 - 127.0.0.11 as listed
                    if (resBytes[0] == 127 && resBytes[1] == 0 && resBytes[2] == 0 && resBytes[3] >= 2 && resBytes[3] <= 11)
                    {
                        return (true, addr.ToString());
                    }
                }
            }
            catch
            {
                // NXDOMAIN -> not listed
            }
        }

        return (false, null);
    }
}
