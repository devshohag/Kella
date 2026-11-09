using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Kella.Core;
using Kella.Core.Actions;
using Kella.Core.Domain;
using Kella.Infrastructure.Data;
using Kella.Infrastructure.Security;

namespace Kella.Infrastructure.Pipeline;

/// <summary>
/// Consumes events, runs every rule interested in the event type, persists findings,
/// opens or joins incidents and queues actions (SPEC §9, §11).
/// TODO(Phase 1): move incident grouping + playbooks into a PlaybookRunner and load playbooks from YAML.
/// </summary>
public sealed class RuleEngineService(
    IEventBus bus,
    IEnumerable<IRule> rules,
    IServiceScopeFactory scopes,
    ILogger<RuleEngineService> log) : BackgroundService
{
    private readonly IRule[] _rules = rules.ToArray();

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        await foreach (var evt in bus.SubscribeAsync(ct))
        {
            foreach (var rule in _rules.Where(r => r.EventTypes.Contains(evt.Type)))
            {
                RuleMatch? match;
                try { match = rule.Evaluate(evt); }
                catch (Exception ex) { log.LogError(ex, "Rule {Rule} failed", rule.Code); continue; }
                if (match is null) continue;

                try { await PersistAsync(evt, match, ct); }
                catch (Exception ex) { log.LogError(ex, "Persisting finding for {Rule} failed", rule.Code); }
            }
        }
    }

    public Task PersistMatchAsync(KellaEvent evt, RuleMatch match, CancellationToken ct = default) =>
        PersistAsync(evt, match, ct);

    private async Task PersistAsync(KellaEvent evt, RuleMatch match, CancellationToken ct)
    {
        using var scope = scopes.CreateScope();
        scope.ServiceProvider.GetRequiredService<OrgContext>().Set(evt.OrganizationId);
        var db = scope.ServiceProvider.GetRequiredService<KellaDbContext>();
        var signer = scope.ServiceProvider.GetRequiredService<CommandSigner>();
        var router = scope.ServiceProvider.GetRequiredService<IAlertRouter>();

        var twoHoursAgo = evt.Ts.AddHours(-2);
        var family = match.RuleCode.Contains('.') ? match.RuleCode.Split('.')[0] : match.RuleCode;

        // Look for open incident with same server, tenant and type family opened within the last 2 hours
        var openIncidents = await db.Incidents
            .Where(i => i.ServerId == evt.ServerId &&
                        i.TenantId == evt.TenantId &&
                        i.Status != IncidentStatus.Resolved &&
                        i.OpenedAt >= twoHoursAgo)
            .OrderByDescending(i => i.OpenedAt)
            .ToListAsync(ct);

        var incident = openIncidents.FirstOrDefault(i =>
            i.Type == family ||
            i.Type.StartsWith(family + ".") ||
            (i.Type.Contains('.') && i.Type.Split('.')[0] == family));

        var isNewIncident = false;
        var severityIncreased = false;
        var newApprovalActionAdded = false;

        if (incident is null)
        {
            isNewIncident = true;
            incident = new Incident
            {
                OrganizationId = evt.OrganizationId,
                Number = await IncidentNumberAllocator.AllocateNextNumberAsync(db, evt.OrganizationId, ct),
                TenantId = evt.TenantId,
                ServerId = evt.ServerId,
                Type = family,
                Subtype = match.RuleCode,
                Severity = match.Severity,
                Title = match.Title,
                Summary = match.Summary,
                OpenedAt = evt.Ts,
            };
            db.Incidents.Add(incident);
        }
        else
        {
            // Join existing incident
            if (match.Severity > incident.Severity)
            {
                incident.Severity = match.Severity;
                severityIncreased = true;
            }
            incident.Summary = $"{incident.Summary}\n{match.Summary}".Trim();
            incident.UpdatedAt = DateTimeOffset.UtcNow;
        }

        db.Findings.Add(new Finding
        {
            OrganizationId = evt.OrganizationId,
            RuleCode = match.RuleCode,
            TenantId = evt.TenantId,
            ServerId = evt.ServerId,
            Severity = match.Severity,
            Title = match.Title,
            Summary = match.Summary,
            Evidence = new(match.Evidence),
            FirstSeen = evt.Ts,
            LastSeen = evt.Ts,
            IncidentId = incident.Id,
        });

        // Expire any queued actions older than their command's expiry (10 minutes)
        var now = DateTimeOffset.UtcNow;
        var staleQueuedThreshold = now.AddMinutes(-10);
        var staleQueuedActions = await db.Actions
            .Where(a => a.ServerId == evt.ServerId && a.Status == ActionStatus.Queued && a.CreatedAt <= staleQueuedThreshold)
            .ToListAsync(ct);
        foreach (var sq in staleQueuedActions)
        {
            sq.Status = ActionStatus.Expired;
        }

        // Query active auto actions on this server to deduplicate auto actions
        var candidateServerActions = await db.Actions
            .Where(a => a.ServerId == evt.ServerId &&
                        (a.Status == ActionStatus.Queued || a.Status == ActionStatus.Sent || a.Status == ActionStatus.Succeeded))
            .ToListAsync(ct);

        var activeServerActions = candidateServerActions.Where(a => IsAutoActionActive(a, now)).ToList();

        var existingIncidentActions = await db.Actions
            .Where(a => a.IncidentId == incident.Id && a.Status != ActionStatus.Rejected && a.Status != ActionStatus.Failed)
            .ToListAsync(ct);

        foreach (var s in match.Actions)
        {
            if (s.Mode == ActionMode.Auto)
            {
                var duplicateAuto = activeServerActions.Any(ea =>
                    ea.Kind == s.Kind &&
                    ParamsEqual(ea.Params, s.Params));
                if (duplicateAuto) continue;
            }
            else
            {
                var duplicatePending = existingIncidentActions.Any(ea =>
                    ea.Kind == s.Kind &&
                    ParamsEqual(ea.Params, s.Params));
                if (duplicatePending) continue;
            }

            DateTimeOffset? expiresAt = null;
            if (s.Mode == ActionMode.Approval)
            {
                expiresAt = DateTimeOffset.UtcNow.AddHours(24);
            }
            else if (s.Mode == ActionMode.Auto)
            {
                if (s.Params.TryGetValue("ttlSec", out var ttlStr) && int.TryParse(ttlStr, out var ttlSec))
                {
                    expiresAt = DateTimeOffset.UtcNow.AddSeconds(ttlSec);
                }
                else
                {
                    expiresAt = DateTimeOffset.UtcNow.AddHours(1);
                }
            }

            var action = new KellaAction
            {
                OrganizationId = evt.OrganizationId,
                IncidentId = incident.Id,
                ServerId = evt.ServerId,
                Kind = s.Kind,
                Params = new(s.Params),
                Mode = s.Mode,
                Label = s.Label,
                Status = s.Mode == ActionMode.Auto ? ActionStatus.Queued : ActionStatus.PendingApproval,
                ExpiresAt = expiresAt,
            };
            db.Actions.Add(action);
            activeServerActions.Add(action);
            existingIncidentActions.Add(action);

            if (s.Mode == ActionMode.Approval)
            {
                newApprovalActionAdded = true;
            }
            else if (s.Mode == ActionMode.Auto)
            {
                db.AgentCommands.Add(AgentCommands.Queue(
                    signer,
                    evt.ServerId,
                    action.Id,
                    s.Kind,
                    s.Params,
                    DateTimeOffset.UtcNow.AddMinutes(10)));
            }
        }

        if (isNewIncident)
        {
            db.AuditLog.Add(new AuditEntry
            {
                OrganizationId = evt.OrganizationId,
                ActorType = "system",
                ActorId = match.RuleCode,
                Verb = "incident.opened",
                Target = $"incident:{incident.Id}",
            });
        }

        await db.SaveChangesAsync(ct);
        log.LogInformation("INC-{Number} processed for rule {Rule}: {Title}", incident.Number, match.RuleCode, match.Title);

        if (isNewIncident || severityIncreased || newApprovalActionAdded)
        {
            try { await router.RouteAsync(incident, ct); }
            catch (Exception ex) { log.LogError(ex, "Routing alerts for INC-{Number} failed", incident.Number); }
        }
    }

    private static bool ParamsEqual(IReadOnlyDictionary<string, string> a, IReadOnlyDictionary<string, string> b)
    {
        if (a.Count != b.Count) return false;
        foreach (var (k, v) in a)
        {
            if (!b.TryGetValue(k, out var bv) || bv != v) return false;
        }
        return true;
    }

    private static bool IsAutoActionActive(KellaAction a, DateTimeOffset now)
    {
        if (a.Status != ActionStatus.Queued && a.Status != ActionStatus.Sent && a.Status != ActionStatus.Succeeded)
            return false;

        if (a.Params.TryGetValue("ttlSec", out var ttlStr) && int.TryParse(ttlStr, out var ttlSec))
        {
            return a.CreatedAt.AddSeconds(ttlSec) > now;
        }

        if (a.ExpiresAt.HasValue && a.Kind != ActionKinds.BlockIp)
        {
            return a.ExpiresAt.Value > now;
        }

        return a.CreatedAt.AddHours(1) > now;
    }
}
