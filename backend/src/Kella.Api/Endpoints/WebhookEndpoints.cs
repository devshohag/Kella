using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Kella.Core.Domain;
using Kella.Infrastructure;
using Kella.Infrastructure.Data;
using Kella.Infrastructure.Security;

namespace Kella.Api.Endpoints;

public static class WebhookEndpoints
{
    public static void MapWebhookEndpoints(this WebApplication app)
    {
        var g = app.MapGroup("/api/hooks").WithTags("Webhooks");

        g.MapPost("/telegram", async (HttpContext http, KellaDbContext db, OrgContext org, CommandSigner signer, CancellationToken ct) =>
        {
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

            // Handle commands: "1", "2" (maps to pending approvals) or "ack"
            if (int.TryParse(text, out var optionNumber) && optionNumber >= 1)
            {
                // Find latest open incident with pending actions
                var pendingAction = await db.Actions
                    .Where(a => a.Status == ActionStatus.PendingApproval && a.ExpiresAt > DateTimeOffset.UtcNow)
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
                        DataJson = $"{{\"source\":\"telegram\",\"chatId\":\"{chatId}\"}}"
                    });

                    await db.SaveChangesAsync(ct);
                }
            }

            return Results.Ok();
        });
    }
}
