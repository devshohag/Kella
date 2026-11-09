using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Kella.Core;
using Kella.Core.Domain;
using Kella.Infrastructure.Data;

namespace Kella.Infrastructure.Pipeline;

public enum DnsblStatus { NotListed, Listed, Unknown }

/// <summary>
/// IP reputation checker (SPEC §17 Phase 2):
/// Checks server public sending IPs periodically (every 15 min).
/// Per SPEC: treat only 127.0.0.2-127.0.0.11 as listed, ignore 127.255.255.x (log resolver refused),
/// and raise a finding/incident on new listing.
/// </summary>
public sealed class IpReputationService(
    IServiceScopeFactory scopes,
    IDnsResolver resolver,
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
            catch (Exception ex) when (!ct.IsCancellationRequested)
            {
                log.LogError(ex, "DNSBL IP reputation check loop encountered an error");
            }

            try
            {
                await Task.Delay(TimeSpan.FromMinutes(15), ct);
            }
            catch (OperationCanceledException) { break; }
        }
    }

    public async Task CheckReputationAsync(CancellationToken ct = default)
    {
        using var scope = scopes.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<KellaDbContext>();

        // Check our sending IPs only (SPEC §9, §17): servers.PublicIp
        var servers = await db.Servers.IgnoreQueryFilters()
            .Where(s => !string.IsNullOrEmpty(s.PublicIp))
            .Select(s => new { s.OrganizationId, ServerId = s.Id, PublicIp = s.PublicIp! })
            .ToListAsync(ct);

        var targets = servers.DistinctBy(x => (x.OrganizationId, x.PublicIp)).ToList();
        var now = DateTimeOffset.UtcNow;

        foreach (var target in targets)
        {
            if (!IPAddress.TryParse(target.PublicIp, out var ip) ||
                ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork ||
                IPAddress.IsLoopback(ip))
            {
                continue;
            }

            var (status, returnCode) = await CheckDnsblAsync(ip, ct);
            if (status == DnsblStatus.Unknown)
            {
                // DNS error / lookup failure -> unknown state, do not change reputation state
                continue;
            }

            var rep = await db.IpReputations.IgnoreQueryFilters()
                .FirstOrDefaultAsync(r => r.OrganizationId == target.OrganizationId && r.Ip == target.PublicIp, ct);

            if (status == DnsblStatus.Listed)
            {
                if (rep == null)
                {
                    rep = new IpReputation
                    {
                        OrganizationId = target.OrganizationId,
                        ServerId = target.ServerId,
                        Ip = target.PublicIp,
                        Listed = true,
                        ReturnCode = returnCode,
                        ListedSince = now,
                        LastChecked = now
                    };
                    db.IpReputations.Add(rep);

                    await OpenIncidentAsync(scope, db, target.OrganizationId, target.ServerId, target.PublicIp, returnCode, now, ct);
                }
                else
                {
                    rep.LastChecked = now;
                    if (!rep.Listed)
                    {
                        // Transition not-listed -> listed
                        rep.Listed = true;
                        rep.ReturnCode = returnCode;
                        rep.ListedSince = now;

                        await OpenIncidentAsync(scope, db, target.OrganizationId, target.ServerId, target.PublicIp, returnCode, now, ct);
                    }
                    else
                    {
                        rep.ReturnCode = returnCode;
                    }
                }
            }
            else // NotListed
            {
                if (rep == null)
                {
                    rep = new IpReputation
                    {
                        OrganizationId = target.OrganizationId,
                        ServerId = target.ServerId,
                        Ip = target.PublicIp,
                        Listed = false,
                        ReturnCode = null,
                        ListedSince = null,
                        LastChecked = now
                    };
                    db.IpReputations.Add(rep);
                }
                else
                {
                    rep.LastChecked = now;
                    if (rep.Listed)
                    {
                        // Transition listed -> not-listed: resolve existing incident
                        rep.Listed = false;
                        rep.ReturnCode = null;
                        rep.ListedSince = null;

                        var openInc = await db.Incidents.IgnoreQueryFilters()
                            .Where(i => i.OrganizationId == target.OrganizationId &&
                                        i.ServerId == target.ServerId &&
                                        i.Type == "mail.ip_reputation" &&
                                        (i.Status == IncidentStatus.Open || i.Status == IncidentStatus.Contained))
                            .OrderByDescending(i => i.OpenedAt)
                            .FirstOrDefaultAsync(ct);

                        if (openInc != null)
                        {
                            openInc.Status = IncidentStatus.Resolved;
                            openInc.ResolvedAt = now;
                            openInc.Summary = $"{openInc.Summary} (Delisted from DNSBL at {now:u})";
                        }
                    }
                }
            }

            await db.SaveChangesAsync(ct);
        }
    }

    private async Task OpenIncidentAsync(
        IServiceScope scope,
        KellaDbContext db,
        Guid organizationId,
        Guid serverId,
        string publicIp,
        string? returnCode,
        DateTimeOffset now,
        CancellationToken ct)
    {
        scope.ServiceProvider.GetRequiredService<OrgContext>().Set(organizationId);
        var alertRouter = scope.ServiceProvider.GetRequiredService<IAlertRouter>();

        var inc = new Incident
        {
            OrganizationId = organizationId,
            ServerId = serverId,
            Type = "mail.ip_reputation",
            Severity = Severity.Warning,
            Title = $"Sending IP {publicIp} listed on DNSBL",
            Summary = $"IP {publicIp} returned {returnCode} on public DNSBL. Outbound deliverability impacted.",
            OpenedAt = now
        };

        db.Incidents.Add(inc);
        await IncidentNumberAllocator.SaveIncidentWithRetryAsync(db, inc, ct);

        db.Findings.Add(new Finding
        {
            OrganizationId = organizationId,
            ServerId = serverId,
            RuleCode = "mail.ip_reputation",
            Severity = Severity.Warning,
            Title = $"DNSBL Blacklisted: {publicIp}",
            Summary = $"Listed on DNSBL with return code {returnCode}. First detected at {now:u}.",
            Evidence = new()
            {
                ["ip"] = publicIp,
                ["returnCode"] = returnCode ?? "",
                ["listedSince"] = now.ToString("O")
            },
            FirstSeen = now,
            LastSeen = now,
            IncidentId = inc.Id
        });

        await db.SaveChangesAsync(ct);

        try
        {
            await alertRouter.RouteAsync(inc, ct);
        }
        catch (Exception ex)
        {
            log.LogError(ex, "Failed to route alert for DNSBL incident {IncidentId} for IP {Ip}", inc.Id, publicIp);
        }
    }

    public async Task<(DnsblStatus Status, string? ReturnCode)> CheckDnsblAsync(
        IPAddress ip, CancellationToken ct = default)
    {
        var bytes = ip.GetAddressBytes();
        var reversed = $"{bytes[3]}.{bytes[2]}.{bytes[1]}.{bytes[0]}";

        bool hasUnknown = false;
        foreach (var zone in DnsblZones)
        {
            var query = $"{reversed}.{zone}";
            var addrs = await resolver.ResolveAsync(query, ct);
            if (addrs == null)
            {
                hasUnknown = true;
                continue;
            }

            foreach (var addr in addrs)
            {
                var resBytes = addr.GetAddressBytes();
                // Check for resolver rate-limit/refusal: 127.255.255.x
                if (resBytes[0] == 127 && resBytes[1] == 255 && resBytes[2] == 255)
                {
                    log.LogWarning("DNSBL zone {Zone} refused query or rate-limited: returned {Code}", zone, addr);
                    continue;
                }

                // SPEC: treat only 127.0.0.2 - 127.0.0.11 as listed
                if (resBytes[0] == 127 && resBytes[1] == 0 && resBytes[2] == 0 && resBytes[3] >= 2 && resBytes[3] <= 11)
                {
                    return (DnsblStatus.Listed, addr.ToString());
                }
            }
        }

        if (hasUnknown)
            return (DnsblStatus.Unknown, null);

        return (DnsblStatus.NotListed, null);
    }
}
