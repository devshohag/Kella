using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Kella.Core.Domain;
using Kella.Infrastructure;
using Kella.Infrastructure.Alerting;
using Kella.Infrastructure.Data;
using Kella.Infrastructure.Security;

namespace Kella.Api.Endpoints;

public static class WebhookEndpoints
{
    private static readonly Regex IncidentNumberRegex = new(@"INC-(\d+)", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public static void MapWebhookEndpoints(this WebApplication app)
    {
        var g = app.MapGroup("/api/hooks").WithTags("Webhooks");

        g.MapPost("/telegram", async (
            HttpContext http,
            KellaDbContext db,
            OrgContext org,
            CommandSigner signer,
            TelegramAlertChannel telegram,
            IConfiguration config,
            IHostEnvironment env,
            ILoggerFactory loggerFactory,
            CancellationToken ct) =>
        {
            // Verify X-Telegram-Bot-Api-Secret-Token with constant-time compare
            var expectedSecret = config["Kella:Telegram:WebhookSecretToken"];
            var isDev = env.IsDevelopment();

            if (string.IsNullOrEmpty(expectedSecret))
            {
                if (!isDev)
                {
                    return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
                }
                var logger = loggerFactory.CreateLogger("Kella.Api.Webhooks");
                logger.LogWarning("Kella:Telegram:WebhookSecretToken is not configured. Webhook is unauthenticated in development.");
            }
            else
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

            // Idempotency: repeated update_id does nothing
            long? updateId = null;
            if (root.TryGetProperty("update_id", out var updateIdElem) && updateIdElem.TryGetInt64(out var uid))
            {
                updateId = uid;
                var alreadyProcessed = await db.TelegramUpdates.AnyAsync(u => u.UpdateId == uid, ct);
                if (alreadyProcessed)
                    return Results.Ok();
            }

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
            AlertDelivery? targetDelivery = null;
            if (msg.TryGetProperty("reply_to_message", out var replyMsg))
            {
                if (replyMsg.TryGetProperty("message_id", out var midElem) && midElem.TryGetInt64(out var rmid))
                {
                    targetDelivery = await db.AlertDeliveries
                        .FirstOrDefaultAsync(d => d.MessageId == rmid, ct);
                }

                if (replyMsg.TryGetProperty("text", out var replyText))
                {
                    var replyStr = replyText.GetString() ?? "";
                    var match = IncidentNumberRegex.Match(replyStr);
                    if (match.Success && int.TryParse(match.Groups[1].Value, out var incNum))
                    {
                        targetIncident = await db.Incidents
                            .FirstOrDefaultAsync(i => i.Number == incNum, ct);
                    }
                }
            }

            if (targetDelivery == null && targetIncident != null)
            {
                targetDelivery = await db.AlertDeliveries
                    .Where(d => d.IncidentId == targetIncident.Id && d.Channel.ToLower() == "telegram")
                    .OrderByDescending(d => d.CreatedAt)
                    .FirstOrDefaultAsync(ct);
            }

            // Handle reply commands (SPEC §12): "1", "2", "ack", "status"
            if (int.TryParse(text, out var optionNumber) && optionNumber >= 1)
            {
                if (targetIncident == null)
                {
                    await telegram.SendMessageAsync(chatId, "Reply to an alert message to approve.", ct);
                    return Results.Ok();
                }

                // Map option N stably to the action ID list stored on the alert delivery (or pending actions fallback)
                var actionIds = targetDelivery is { ActionIds.Count: > 0 }
                    ? targetDelivery.ActionIds
                    : await db.Actions
                        .Where(a => a.IncidentId == targetIncident.Id && a.Status == ActionStatus.PendingApproval && (a.ExpiresAt == null || a.ExpiresAt > DateTimeOffset.UtcNow))
                        .OrderBy(a => a.CreatedAt)
                        .ThenBy(a => a.Id)
                        .Select(a => a.Id)
                        .ToListAsync(ct);

                if (optionNumber <= actionIds.Count)
                {
                    var targetActionId = actionIds[optionNumber - 1];
                    var pendingAction = await db.Actions
                        .FirstOrDefaultAsync(a => a.Id == targetActionId, ct);

                    if (pendingAction != null && pendingAction.Status == ActionStatus.PendingApproval &&
                        (pendingAction.ExpiresAt == null || pendingAction.ExpiresAt > DateTimeOffset.UtcNow))
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

                        if (updateId.HasValue)
                        {
                            db.TelegramUpdates.Add(new TelegramUpdate { UpdateId = updateId.Value, ProcessedAt = DateTimeOffset.UtcNow });
                        }

                        await db.SaveChangesAsync(ct);
                        await telegram.SendMessageAsync(chatId, $"Approved action {optionNumber} for INC-{targetIncident.Number}.", ct);
                        return Results.Ok();
                    }
                }

                // Invalid option number or action already approved/not pending
                await telegram.SendMessageAsync(chatId, $"No pending action {optionNumber}", ct);
                if (updateId.HasValue)
                {
                    db.TelegramUpdates.Add(new TelegramUpdate { UpdateId = updateId.Value, ProcessedAt = DateTimeOffset.UtcNow });
                    await db.SaveChangesAsync(ct);
                }
                return Results.Ok();
            }
            else if (text.Equals("ack", StringComparison.OrdinalIgnoreCase))
            {
                if (targetIncident == null)
                {
                    await telegram.SendMessageAsync(chatId, "Reply to an alert message to acknowledge.", ct);
                    return Results.Ok();
                }

                targetIncident.AcknowledgedAt = DateTimeOffset.UtcNow;
                targetIncident.AcknowledgedBy = $"telegram:{user.Email}";

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
                        user = user.Email,
                        incident_number = targetIncident.Number
                    })
                });

                if (updateId.HasValue)
                {
                    db.TelegramUpdates.Add(new TelegramUpdate { UpdateId = updateId.Value, ProcessedAt = DateTimeOffset.UtcNow });
                }

                await db.SaveChangesAsync(ct);
                await telegram.SendMessageAsync(chatId, $"Acknowledged INC-{targetIncident.Number}", ct);
            }
            else if (text.Equals("status", StringComparison.OrdinalIgnoreCase))
            {
                if (targetIncident == null)
                {
                    await telegram.SendMessageAsync(chatId, "Reply to an alert message to view status.", ct);
                    return Results.Ok();
                }

                db.AuditLog.Add(new AuditEntry
                {
                    OrganizationId = user.OrganizationId,
                    ActorType = "user",
                    ActorId = user.Id.ToString(),
                    Verb = "incident.status_queried",
                    Target = $"incident:{targetIncident.Id}",
                    DataJson = JsonSerializer.Serialize(new
                    {
                        source = "telegram",
                        chatId,
                        user = user.Email,
                        incident_number = targetIncident.Number
                    })
                });

                if (updateId.HasValue)
                {
                    db.TelegramUpdates.Add(new TelegramUpdate { UpdateId = updateId.Value, ProcessedAt = DateTimeOffset.UtcNow });
                }

                await db.SaveChangesAsync(ct);

                var statusSummary = $"INC-{targetIncident.Number}: {targetIncident.Title}\nStatus: {targetIncident.Status}\nSeverity: {targetIncident.Severity}\n{targetIncident.Summary}";
                await telegram.SendMessageAsync(chatId, statusSummary, ct);
            }

            return Results.Ok();
        });
    }
}
