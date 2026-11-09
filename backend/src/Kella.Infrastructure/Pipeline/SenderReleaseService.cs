using System.Text.Json;
using Kella.Core.Actions;
using Kella.Core.Domain;
using Kella.Core.Rules;
using Kella.Infrastructure.Data;
using Kella.Infrastructure.Security;
using Microsoft.EntityFrameworkCore;

namespace Kella.Infrastructure.Pipeline;

/// <summary>
/// Queues <c>release_sender</c> through the same actions + signed commands + audit path for both
/// manual releases (dashboard/Telegram) and the automatic hold TTL (SPEC §8.5, §11).
/// </summary>
public sealed class SenderReleaseService(KellaDbContext db, CommandSigner signer)
{
    public const int DefaultHoldTtlSeconds = MailDefaults.HoldTtlSeconds;

    public async Task<int> QueueForIncidentAsync(
        Guid incidentId, string actorType, string actorId, string source, CancellationToken ct = default)
    {
        var holds = await db.Actions
            .Where(a => a.IncidentId == incidentId &&
                        a.Kind == ActionKinds.HoldSender &&
                        (a.Status == ActionStatus.Queued || a.Status == ActionStatus.Sent || a.Status == ActionStatus.Succeeded))
            .OrderBy(a => a.CreatedAt)
            .ToListAsync(ct);

        return await QueueAsync(holds, actorType, actorId, source, ct);
    }

    public async Task<int> QueueForActionAsync(
        Guid holdActionId, string actorType, string actorId, string source, CancellationToken ct = default)
    {
        var hold = await db.Actions
            .FirstOrDefaultAsync(a => a.Id == holdActionId && a.Kind == ActionKinds.HoldSender, ct);
        if (hold is null) return 0;

        return await QueueAsync([hold], actorType, actorId, source, ct);
    }

    private async Task<int> QueueAsync(
        IReadOnlyList<KellaAction> holds, string actorType, string actorId, string source, CancellationToken ct)
    {
        if (holds.Count == 0) return 0;

        var serverIds = holds.Select(h => h.ServerId).Distinct().ToList();
        var existingReleases = await db.Actions
            .Where(a => serverIds.Contains(a.ServerId) &&
                        a.Kind == ActionKinds.ReleaseSender &&
                        (a.Status == ActionStatus.PendingApproval ||
                         a.Status == ActionStatus.Queued ||
                         a.Status == ActionStatus.Sent ||
                         a.Status == ActionStatus.Succeeded))
            .ToListAsync(ct);

        var queued = 0;
        foreach (var hold in holds)
        {
            if (hold.Status is not (ActionStatus.Queued or ActionStatus.Sent or ActionStatus.Succeeded))
                continue;
            if (!hold.Params.TryGetValue("sender", out var sender) || string.IsNullOrWhiteSpace(sender))
                continue;
            if (existingReleases.Any(r =>
                    r.ServerId == hold.ServerId &&
                    r.Params.TryGetValue("sender", out var existingSender) &&
                    string.Equals(existingSender, sender, StringComparison.OrdinalIgnoreCase)))
                continue;

            var release = new KellaAction
            {
                OrganizationId = hold.OrganizationId,
                IncidentId = hold.IncidentId,
                ServerId = hold.ServerId,
                Kind = ActionKinds.ReleaseSender,
                Params = new() { ["sender"] = sender },
                Mode = ActionMode.Approval,
                Status = ActionStatus.Queued,
                Label = $"Release held sender {sender}",
                RequestedBy = actorId,
                ApprovedBy = actorType == "user" ? actorId : null,
            };
            db.Actions.Add(release);
            existingReleases.Add(release);

            db.AgentCommands.Add(AgentCommands.Queue(
                signer,
                release.ServerId,
                release.Id,
                release.Kind,
                release.Params,
                DateTimeOffset.UtcNow.AddMinutes(10)));

            db.AuditLog.Add(new AuditEntry
            {
                OrganizationId = release.OrganizationId,
                ActorType = actorType,
                ActorId = actorId,
                Verb = "action.released",
                Target = $"action:{release.Id}",
                DataJson = JsonSerializer.Serialize(new
                {
                    source,
                    sender,
                    holdActionId = hold.Id,
                    incidentId = hold.IncidentId,
                }),
            });
            queued++;
        }

        if (queued > 0) await db.SaveChangesAsync(ct);
        return queued;
    }
}
