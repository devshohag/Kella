using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Kella.Core.Domain;
using Kella.Infrastructure;
using Kella.Infrastructure.Data;
using Kella.Infrastructure.Security;

namespace Kella.Api.Endpoints;

public static class WebhookEndpoints
{
    private static readonly Regex IncidentNumberRegex = new(@"INC-(\d+)", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public static void MapWebhookEndpoints(this WebApplication app)
    {
        var g = app.MapGroup("/api/hooks").WithTags("Webhooks");

        g.MapPost("/telegram", async (HttpContext http, KellaDbContext db, OrgContext org, CommandSigner signer, IConfiguration config, CancellationToken ct) =>
        {
            // Verify X-Telegram-Bot-Api-Secret-Token with constant-time compare
            var expectedSecret = config["Kella:Telegram:WebhookSecretToken"];
            if (!string.IsNullOrEmpty(expectedSecret))
            {
                var headerSecret = http.Request.Headers["X-Telegram-Bot-Api-Secret-Token"].ToString();
                if (string.IsNullOrEmpty(headerSecret) || !CryptographicOperations.FixedTimeEquals(
                    Encoding.UTF8.GetBytes(expectedSecret),
                    Encoding.UTF8.GetBytes(headerSecret)))
                {
                    return Results.Unauthorized();
                }
            }

            using var reader = new StreamReader(http.Request.Body);
            var body = await reader.ReadToEndAsync(ct);

            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;

            if (!root.TryGetProperty("message", out var msg))
                return Results.Ok();

            if (!msg.TryGetProperty("chat", out var chat) || !chat.TryGetProperty("id", out var chatIdElem))
                return Results.Ok();

            var chatId = chatIdElem.ToString();
            var text = msg.TryGetProperty("text", out var t) ? t.GetString()?.Trim() : null;

            if (string.IsNullOrWhiteSpace(text))
                return Results.Ok();

            // Find user by Telegram chat ID (bypass org query filter)
            var user = await db.Users.IgnoreQueryFilters()
                .FirstOrDefaultAsync(u => u.TelegramChatId == chatId, ct);

            if (user is null || user.Role == UserRole.Viewer)
                return Results.Ok(); // Ignored or unauthorized

            org.Set(user.OrganizationId);

            // Determine if the message is replying to an alert message
            Incident? targetIncident = null;
            if (msg.TryGetProperty("reply_to_message", out var replyMsg) &&
                replyMsg.TryGetProperty("text", out var replyText))
            {
                var replyStr = replyText.GetString() ?? "";
                var match = IncidentNumberRegex.Match(replyStr);
                if (match.Success && int.TryParse(match.Groups[1].Value, out var incNum))
                {
                    targetIncident = await db.Incidents
                        .FirstOrDefaultAsync(i => i.Number == incNum, ct);
                }
            }

            // Handle reply commands (SPEC §12): "1", "2", "ack", "status"
            if (int.TryParse(text, out var optionNumber) && optionNumber >= 1)
            {
                // Must map to the pending actions of the incident the replied-to alert belongs to
                var query = db.Actions.Where(a => a.Status == ActionStatus.PendingApproval && a.ExpiresAt > DateTimeOffset.UtcNow);
                if (targetIncident != null)
                {
                    query = query.Where(a => a.IncidentId == targetIncident.Id);
                }
                else
                {
                    // Fallback to latest open incident with pending actions
                    var latestIncidentId = await db.Incidents
                        .Where(i => i.Status != IncidentStatus.Resolved)
                        .OrderByDescending(i => i.OpenedAt)
                        .Select(i => i.Id)
                        .FirstOrDefaultAsync(ct);

                    if (latestIncidentId != Guid.Empty)
                        query = query.Where(a => a.IncidentId == latestIncidentId);
                }

                var pendingAction = await query
                    .OrderBy(a => a.CreatedAt)
                    .Skip(optionNumber - 1)
                    .FirstOrDefaultAsync(ct);

                if (pendingAction != null)
                {
                    pendingAction.Status = ActionStatus.Queued;
                    pendingAction.ApprovedBy = $"telegram:{user.Email}";

                    db.AgentCommands.Add(AgentCommands.Queue(
                        signer,
                        pendingAction.ServerId,
                        pendingAction.Id,
                        pendingAction.Kind,
                        new Dictionary<string, string>(pendingAction.Params),
                        DateTimeOffset.UtcNow.AddMinutes(10)));

                    db.AuditLog.Add(new AuditEntry
                    {
                        OrganizationId = pendingAction.OrganizationId,
                        ActorType = "user",
                        ActorId = user.Id.ToString(),
                        Verb = "action.approved",
                        Target = $"action:{pendingAction.Id}",
                        DataJson = JsonSerializer.Serialize(new
                        {
                            source = "telegram",
                            chatId,
                            optionNumber,
                            actionId = pendingAction.Id,
                            incidentId = pendingAction.IncidentId
                        })
                    });

                    await db.SaveChangesAsync(ct);
                }
            }
            else if (text.Equals("ack", StringComparison.OrdinalIgnoreCase))
            {
                // Acknowledge incident
                if (targetIncident != null)
                {
                    db.AuditLog.Add(new AuditEntry
                    {
                        OrganizationId = targetIncident.OrganizationId,
                        ActorType = "user",
                        ActorId = user.Id.ToString(),
                        Verb = "incident.acknowledged",
                        Target = $"incident:{targetIncident.Id}",
                        DataJson = JsonSerializer.Serialize(new
                        {
                            source = "telegram",
                            chatId,
                            user = user.Email
                        })
                    });
                    await db.SaveChangesAsync(ct);
                }
            }
            else if (text.Equals("status", StringComparison.OrdinalIgnoreCase))
            {
                // status command requested; log audit entry
                db.AuditLog.Add(new AuditEntry
                {
                    OrganizationId = user.OrganizationId,
                    ActorType = "user",
                    ActorId = user.Id.ToString(),
                    Verb = "incident.status_queried",
                    Target = targetIncident != null ? $"incident:{targetIncident.Id}" : "org",
                    DataJson = JsonSerializer.Serialize(new
                    {
                        source = "telegram",
                        chatId,
                        user = user.Email
                    })
                });
                await db.SaveChangesAsync(ct);
            }

            return Results.Ok();
        });
    }
}
