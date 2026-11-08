using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Kella.Api;
using Kella.Core;
using Kella.Core.Domain;
using Kella.Infrastructure.Data;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Kella.Tests;

public class WebhookSecurityTests(WebApplicationFactory<Program> factory) : IClassFixture<WebApplicationFactory<Program>>
{
    private const string SecretToken = "super-secret-telegram-webhook-token";

    private readonly WebApplicationFactory<Program> _factory = factory.WithWebHostBuilder(b =>
    {
        b.UseEnvironment("Testing");
        b.UseSetting("ConnectionStrings:Postgres", "");
        b.UseSetting("Kella:Jwt:Key", "kella-testing-only-signing-key-32b");
        b.UseSetting("Kella:Seed:OwnerPassword", "test-owner-password");
        b.UseSetting("Kella:Telegram:WebhookSecretToken", SecretToken);
        b.UseSetting("Kella:Commands:PrivateKey", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
    });

    [Fact]
    public async Task Telegram_webhook_rejects_missing_or_invalid_secret_token()
    {
        var client = _factory.CreateClient();

        // No header -> 401
        var resNoHeader = await client.PostAsJsonAsync("/api/hooks/telegram", new { });
        Assert.Equal(HttpStatusCode.Unauthorized, resNoHeader.StatusCode);

        // Wrong header -> 401
        var reqWrong = new HttpRequestMessage(HttpMethod.Post, "/api/hooks/telegram")
        {
            Content = JsonContent.Create(new { })
        };
        reqWrong.Headers.Add("X-Telegram-Bot-Api-Secret-Token", "wrong-token");
        var resWrong = await client.SendAsync(reqWrong);
        Assert.Equal(HttpStatusCode.Unauthorized, resWrong.StatusCode);

        // Correct header -> 200
        var reqCorrect = new HttpRequestMessage(HttpMethod.Post, "/api/hooks/telegram")
        {
            Content = JsonContent.Create(new { })
        };
        reqCorrect.Headers.Add("X-Telegram-Bot-Api-Secret-Token", SecretToken);
        var resCorrect = await client.SendAsync(reqCorrect);
        Assert.Equal(HttpStatusCode.OK, resCorrect.StatusCode);
    }

    [Fact]
    public async Task Telegram_webhook_fails_closed_when_secret_not_configured_in_production()
    {
        using var prodFactory = new WebApplicationFactory<Program>().WithWebHostBuilder(b =>
        {
            b.UseEnvironment("Production");
            b.UseSetting("ConnectionStrings:Postgres", "");
            b.UseSetting("Kella:Jwt:Key", "production-test-jwt-key-minimum-32-bytes!");
            b.UseSetting("Kella:Seed:OwnerEmail", "owner@example.com");
            b.UseSetting("Kella:Seed:OwnerPassword", "owner-secure-password-123");
            b.UseSetting("Kella:Commands:PrivateKey", Convert.ToBase64String(new byte[32].Select((_, i) => (byte)(i + 1)).ToArray()));
            b.UseSetting("Kella:Telegram:WebhookSecretToken", ""); // empty in Production
        });

        var client = prodFactory.CreateClient();
        var res = await client.PostAsJsonAsync("/api/hooks/telegram", new { });
        Assert.Equal(HttpStatusCode.ServiceUnavailable, res.StatusCode);
    }

    [Fact]
    public void TelegramAlertChannel_Format_contains_incident_number_in_first_line()
    {
        var msg = new AlertMessage(Guid.NewGuid(), 4242, Severity.Critical, "Spike 2", "Body", []);
        var formatted = Kella.Infrastructure.Alerting.TelegramAlertChannel.Format(msg);
        var firstLine = formatted.Split('\n')[0];
        Assert.Contains("INC-4242", firstLine);
    }

    [Fact]
    public async Task Telegram_webhook_reply_approves_only_replied_incident_actions()
    {
        var client = _factory.CreateClient();

        Guid orgId;
        Guid serverId;
        Guid inc1Id;
        Guid inc2Id;
        Guid act1Id;
        Guid act2Id;

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<KellaDbContext>();
            var org = new Organization { Name = "Org Webhook Test" };
            db.Organizations.Add(org);

            var user = new User
            {
                OrganizationId = org.Id,
                Email = "responder@test.org",
                Name = "Responder",
                Role = UserRole.Responder,
                TelegramChatId = "123456"
            };
            db.Users.Add(user);

            var server = new Server { OrganizationId = org.Id, Name = "srv-1" };
            db.Servers.Add(server);

            var inc1 = new Incident
            {
                OrganizationId = org.Id,
                ServerId = server.Id,
                Number = 2001,
                Type = "mail.outbound_spike",
                Title = "Spike 1",
                Status = IncidentStatus.Open
            };
            var inc2 = new Incident
            {
                OrganizationId = org.Id,
                ServerId = server.Id,
                Number = 2002,
                Type = "mail.outbound_spike",
                Title = "Spike 2",
                Status = IncidentStatus.Open
            };
            db.Incidents.AddRange(inc1, inc2);

            var act1 = new KellaAction
            {
                OrganizationId = org.Id,
                IncidentId = inc1.Id,
                ServerId = server.Id,
                Kind = "hold_sender",
                Params = new() { ["sender"] = "user1@bad.com" },
                Status = ActionStatus.PendingApproval,
                ExpiresAt = DateTimeOffset.UtcNow.AddHours(24)
            };
            var act2 = new KellaAction
            {
                OrganizationId = org.Id,
                IncidentId = inc2.Id,
                ServerId = server.Id,
                Kind = "hold_sender",
                Params = new() { ["sender"] = "user2@bad.com" },
                Status = ActionStatus.PendingApproval,
                ExpiresAt = DateTimeOffset.UtcNow.AddHours(24)
            };
            db.Actions.AddRange(act1, act2);

            await db.SaveChangesAsync();

            orgId = org.Id;
            serverId = server.Id;
            inc1Id = inc1.Id;
            inc2Id = inc2.Id;
            act1Id = act1.Id;
            act2Id = act2.Id;
        }

        // Format alert using TelegramAlertChannel.Format per G2
        var alertMessage = new AlertMessage(inc2Id, 2002, Severity.Critical, "Spike 2", "Spike 2 body", ["hold user2@bad.com"]);
        var formattedAlert = Kella.Infrastructure.Alerting.TelegramAlertChannel.Format(alertMessage);

        // Send a webhook reply "1" replying to the formatted alert message
        var payload = new
        {
            message = new
            {
                chat = new { id = "123456" },
                text = "1",
                reply_to_message = new
                {
                    text = formattedAlert
                }
            }
        };

        var req = new HttpRequestMessage(HttpMethod.Post, "/api/hooks/telegram")
        {
            Content = JsonContent.Create(payload)
        };
        req.Headers.Add("X-Telegram-Bot-Api-Secret-Token", SecretToken);

        var res = await client.SendAsync(req);
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<KellaDbContext>();
            var action1 = await db.Actions.IgnoreQueryFilters().FirstAsync(a => a.Id == act1Id);
            var action2 = await db.Actions.IgnoreQueryFilters().FirstAsync(a => a.Id == act2Id);

            // act1 must remain PendingApproval! Only act2 from INC-2002 should be approved!
            Assert.Equal(ActionStatus.PendingApproval, action1.Status);
            Assert.Equal(ActionStatus.Queued, action2.Status);
            Assert.Equal("telegram:responder@test.org", action2.ApprovedBy);
        }
    }
}
