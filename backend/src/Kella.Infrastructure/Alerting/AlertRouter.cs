using Kella.Core;
using Kella.Core.Domain;
using Kella.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace Kella.Infrastructure.Alerting;

/// <summary>
/// Routes one incident to the organization's configured channels and records every delivery
/// (SPEC §12). The dashboard is always an implicit channel. A channel without an implementation
/// (email/WhatsApp/voice in Phase 1) is recorded as skipped instead of silently disappearing.
/// </summary>
public sealed class AlertRouter(
    KellaDbContext db,
    IEnumerable<IAlertChannel> channels,
    ILogger<AlertRouter> log) : IAlertRouter
{
    private static readonly IReadOnlyDictionary<Severity, string[]> Defaults =
        new Dictionary<Severity, string[]>
        {
            [Severity.Info] = ["dashboard"],
            [Severity.Warning] = ["dashboard", "telegram"],
            [Severity.Critical] = ["dashboard", "email", "telegram", "whatsapp"],
            [Severity.Down] = ["dashboard", "email", "telegram", "whatsapp", "voice"],
        };

    private readonly IAlertChannel[] _channels = channels.ToArray();

    public async Task RouteAsync(Incident incident, CancellationToken ct)
    {
        var pendingActions = await db.Actions
            .Where(a => a.IncidentId == incident.Id && a.Status == ActionStatus.PendingApproval)
            .OrderBy(a => a.CreatedAt).ThenBy(a => a.Id)
            .ToListAsync(ct);
        var pendingActionIds = pendingActions.Select(a => a.Id).ToList();
        var approvals = pendingActions
            .Select(a => a.Label ?? a.Kind)
            .ToList();

        var priorDeliveries = await db.AlertDeliveries
            .Where(d => d.IncidentId == incident.Id && d.Status == "sent")
            .OrderBy(d => d.CreatedAt)
            .ToListAsync(ct);

        if (priorDeliveries.Count > 0)
        {
            var maxPriorSeverity = priorDeliveries.Max(d => d.Severity ?? Severity.Info);
            bool severityIncreased = incident.Severity > maxPriorSeverity;

            var priorActionIds = priorDeliveries.SelectMany(d => d.ActionIds).ToHashSet();
            bool newApprovalAction = pendingActionIds.Any(id => !priorActionIds.Contains(id));

            if (!severityIncreased && !newApprovalAction)
            {
                return;
            }
        }

        var configured = await db.AlertRoutes
            .Where(r => r.Severity == incident.Severity)
            .Select(r => r.Channels)
            .FirstOrDefaultAsync(ct);
        var selected = configured is { Count: > 0 } ? configured : Defaults[incident.Severity].ToList();

        var server = incident.ServerId is { } serverId
            ? await db.Servers.FirstOrDefaultAsync(s => s.Id == serverId, ct)
            : null;

        var message = new AlertMessage(
            incident.Id,
            incident.Number,
            incident.Severity,
            incident.Title,
            BuildBody(incident, server),
            approvals);

        foreach (var raw in selected.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (raw.Equals("dashboard", StringComparison.OrdinalIgnoreCase))
            {
                var d = Delivery(incident, "dashboard", "dashboard", "sent");
                d.Severity = incident.Severity;
                d.ActionIds = pendingActionIds;
                db.AlertDeliveries.Add(d);
                continue;
            }

            if (!Enum.TryParse<AlertChannelKind>(raw, true, out var kind))
            {
                log.LogWarning("Unknown alert channel {Channel} for INC-{Number}", raw, incident.Number);
                var d = Delivery(incident, raw, "(unknown channel)", "skipped");
                d.Severity = incident.Severity;
                d.ActionIds = pendingActionIds;
                db.AlertDeliveries.Add(d);
                continue;
            }

            var channel = _channels.FirstOrDefault(c => c.Kind == kind);
            if (channel is null)
            {
                // SPEC §12 defaults include email/WhatsApp/voice for critical and down, but Phase 1
                // only ships Telegram. Keep the row so the UI can show what is not configured yet.
                log.LogWarning("Alert channel {Channel} is not implemented yet (INC-{Number})", raw, incident.Number);
                var d = Delivery(incident, raw, "(not implemented)", "skipped");
                d.Severity = incident.Severity;
                d.ActionIds = pendingActionIds;
                db.AlertDeliveries.Add(d);
                continue;
            }

            var recipients = await RecipientsAsync(kind, ct);
            if (recipients.Count == 0)
            {
                log.LogWarning("No {Channel} recipient configured for INC-{Number}", raw, incident.Number);
                var d = Delivery(incident, raw, "(no recipient)", "skipped");
                d.Severity = incident.Severity;
                d.ActionIds = pendingActionIds;
                db.AlertDeliveries.Add(d);
                continue;
            }

            foreach (var recipient in recipients)
            {
                var delivery = Delivery(incident, raw, recipient.Email, "pending");
                delivery.Severity = incident.Severity;
                delivery.ActionIds = pendingActionIds;
                delivery.ChatId = kind == AlertChannelKind.Telegram ? recipient.TelegramChatId : null;
                db.AlertDeliveries.Add(delivery);
                try
                {
                    long? replyTo = null;
                    if (kind == AlertChannelKind.Telegram && !string.IsNullOrWhiteSpace(recipient.TelegramChatId))
                    {
                        replyTo = priorDeliveries
                            .Where(d => d.Channel.Equals("telegram", StringComparison.OrdinalIgnoreCase) &&
                                        d.MessageId != null &&
                                        (string.Equals(d.ChatId, recipient.TelegramChatId, StringComparison.Ordinal) ||
                                         (d.ChatId == null && string.Equals(d.Recipient, recipient.Email, StringComparison.OrdinalIgnoreCase))))
                            .OrderByDescending(d => d.CreatedAt)
                            .ThenByDescending(d => d.MessageId)
                            .Select(d => d.MessageId)
                            .FirstOrDefault();
                    }

                    var outbound = replyTo.HasValue ? message with { ReplyToMessageId = replyTo } : message;
                    var sentMid = await channel.SendAsync(recipient, outbound, ct);
                    delivery.Status = "sent";
                    delivery.SentAt = DateTimeOffset.UtcNow;
                    delivery.MessageId = sentMid;
                }
                catch (Exception ex)
                {
                    delivery.Status = "failed";
                    log.LogError(ex, "Sending {Channel} alert for INC-{Number} to {Recipient} failed",
                        raw, incident.Number, recipient.Email);
                }
            }
        }

        await db.SaveChangesAsync(ct);
    }

    private async Task<List<User>> RecipientsAsync(AlertChannelKind kind, CancellationToken ct)
    {
        // Responder and above may receive alerts (SPEC §12). The org filter scopes this query.
        var users = await db.Users
            .Where(u => u.Role != UserRole.Viewer)
            .OrderBy(u => u.Role).ThenBy(u => u.Email)
            .ToListAsync(ct);

        return kind == AlertChannelKind.Telegram
            ? users.Where(u => !string.IsNullOrWhiteSpace(u.TelegramChatId)).ToList()
            : users;
    }

    private static AlertDelivery Delivery(Incident incident, string channel, string recipient, string status) => new()
    {
        OrganizationId = incident.OrganizationId,
        IncidentId = incident.Id,
        Channel = channel,
        Recipient = recipient,
        Status = status,
        SentAt = status == "sent" ? DateTimeOffset.UtcNow : null,
    };

    private static string BuildBody(Incident incident, Server? server)
    {
        var lines = new List<string>();
        if (!string.IsNullOrWhiteSpace(incident.Summary)) lines.Add(incident.Summary);
        if (server is not null)
            lines.Add($"Server: {server.Name} ({server.PublicIp ?? server.Hostname})");
        return string.Join('\n', lines);
    }
}
