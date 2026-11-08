using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Kella.Core;
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

    private async Task PersistAsync(KellaEvent evt, RuleMatch match, CancellationToken ct)
    {
        using var scope = scopes.CreateScope();
        scope.ServiceProvider.GetRequiredService<OrgContext>().Set(evt.OrganizationId);
        var db = scope.ServiceProvider.GetRequiredService<KellaDbContext>();
        var signer = scope.ServiceProvider.GetRequiredService<CommandSigner>();
        var router = scope.ServiceProvider.GetRequiredService<IAlertRouter>();

        var incident = new Incident
        {
            OrganizationId = evt.OrganizationId,
            Number = (db.Incidents.Max(i => (int?)i.Number) ?? 2000) + 1,
            TenantId = evt.TenantId,
            ServerId = evt.ServerId,
            Type = match.RuleCode,
            Severity = match.Severity,
            Title = match.Title,
            Summary = match.Summary,
        };
        db.Incidents.Add(incident);

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

        foreach (var s in match.Actions)
        {
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
                ExpiresAt = s.Mode == ActionMode.Approval ? DateTimeOffset.UtcNow.AddHours(24) : null,
            };
            db.Actions.Add(action);

            if (s.Mode == ActionMode.Auto)
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

        db.AuditLog.Add(new AuditEntry
        {
            OrganizationId = evt.OrganizationId,
            ActorType = "system",
            ActorId = match.RuleCode,
            Verb = "incident.opened",
            Target = $"incident:{incident.Id}",
        });

        await db.SaveChangesAsync(ct);
        log.LogInformation("INC-{Number} opened by {Rule}: {Title}", incident.Number, match.RuleCode, match.Title);

        try { await router.RouteAsync(incident, ct); }
        catch (Exception ex) { log.LogError(ex, "Routing alerts for INC-{Number} failed", incident.Number); }
    }
}
