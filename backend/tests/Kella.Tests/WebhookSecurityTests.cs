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

    [Fact]
    public async Task Telegram_webhook_duplicate_update_id_is_idempotent()
    {
        var client = _factory.CreateClient();
        Guid incId;
        Guid act1Id;
        Guid act2Id;

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<KellaDbContext>();
            var org = new Organization { Name = "Org Idempotent Test" };
            db.Organizations.Add(org);

            var user = new User
            {
                OrganizationId = org.Id,
                Email = "idem_resp@test.org",
                Name = "Idem Responder",
                Role = UserRole.Responder,
                TelegramChatId = "555555"
            };
            db.Users.Add(user);

            var server = new Server { OrganizationId = org.Id, Name = "srv-idem" };
            db.Servers.Add(server);

            var inc = new Incident
            {
                OrganizationId = org.Id,
                ServerId = server.Id,
                Number = 3001,
                Type = "mail.outbound_spike",
                Title = "Spike Idem",
                Status = IncidentStatus.Open
            };
            db.Incidents.Add(inc);

            var act1 = new KellaAction
            {
                OrganizationId = org.Id,
                IncidentId = inc.Id,
                ServerId = server.Id,
                Kind = "hold_sender",
                Params = new() { ["sender"] = "idem1@bad.com" },
                Status = ActionStatus.PendingApproval,
                CreatedAt = DateTimeOffset.UtcNow.AddMinutes(-2),
                ExpiresAt = DateTimeOffset.UtcNow.AddHours(24)
            };
            var act2 = new KellaAction
            {
                OrganizationId = org.Id,
                IncidentId = inc.Id,
                ServerId = server.Id,
                Kind = "hold_sender",
                Params = new() { ["sender"] = "idem2@bad.com" },
                Status = ActionStatus.PendingApproval,
                CreatedAt = DateTimeOffset.UtcNow.AddMinutes(-1),
                ExpiresAt = DateTimeOffset.UtcNow.AddHours(24)
            };
            db.Actions.AddRange(act1, act2);
            await db.SaveChangesAsync();

            incId = inc.Id;
            act1Id = act1.Id;
            act2Id = act2.Id;
        }

        var alert = new AlertMessage(incId, 3001, Severity.Critical, "Spike Idem", "Body", ["hold idem1", "hold idem2"]);
        var alertText = Kella.Infrastructure.Alerting.TelegramAlertChannel.Format(alert);

        var payload = new
        {
            update_id = 888123L,
            message = new
            {
                chat = new { id = "555555" },
                text = "1",
                reply_to_message = new { text = alertText }
            }
        };

        // First delivery
        var req1 = new HttpRequestMessage(HttpMethod.Post, "/api/hooks/telegram") { Content = JsonContent.Create(payload) };
        req1.Headers.Add("X-Telegram-Bot-Api-Secret-Token", SecretToken);
        var res1 = await client.SendAsync(req1);
        Assert.Equal(HttpStatusCode.OK, res1.StatusCode);

        // Second delivery with identical update_id
        var req2 = new HttpRequestMessage(HttpMethod.Post, "/api/hooks/telegram") { Content = JsonContent.Create(payload) };
        req2.Headers.Add("X-Telegram-Bot-Api-Secret-Token", SecretToken);
        var res2 = await client.SendAsync(req2);
        Assert.Equal(HttpStatusCode.OK, res2.StatusCode);

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<KellaDbContext>();
            var action1 = await db.Actions.IgnoreQueryFilters().FirstAsync(a => a.Id == act1Id);
            var action2 = await db.Actions.IgnoreQueryFilters().FirstAsync(a => a.Id == act2Id);

            // Exactly one action should be approved; action 2 must NOT be approved on repeated update_id!
            Assert.Equal(ActionStatus.Queued, action1.Status);
            Assert.Equal(ActionStatus.PendingApproval, action2.Status);
        }
    }

    [Fact]
    public async Task Telegram_webhook_reply_without_reply_to_message_approves_nothing()
    {
        var client = _factory.CreateClient();
        Guid actId;

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<KellaDbContext>();
            var org = new Organization { Name = "Org NoReply Test" };
            db.Organizations.Add(org);

            var user = new User
            {
                OrganizationId = org.Id,
                Email = "noreply_user@test.org",
                Name = "NoReply User",
                Role = UserRole.Responder,
                TelegramChatId = "666666"
            };
            db.Users.Add(user);

            var server = new Server { OrganizationId = org.Id, Name = "srv-noreply" };
            db.Servers.Add(server);

            var inc = new Incident
            {
                OrganizationId = org.Id,
                ServerId = server.Id,
                Number = 4001,
                Type = "mail.outbound_spike",
                Title = "Spike NoReply",
                Status = IncidentStatus.Open
            };
            db.Incidents.Add(inc);

            var act = new KellaAction
            {
                OrganizationId = org.Id,
                IncidentId = inc.Id,
                ServerId = server.Id,
                Kind = "hold_sender",
                Params = new() { ["sender"] = "noreply@bad.com" },
                Status = ActionStatus.PendingApproval,
                ExpiresAt = DateTimeOffset.UtcNow.AddHours(24)
            };
            db.Actions.Add(act);
            await db.SaveChangesAsync();

            actId = act.Id;
        }

        // Send "1" WITHOUT reply_to_message
        var payload = new
        {
            update_id = 999123L,
            message = new
            {
                chat = new { id = "666666" },
                text = "1"
            }
        };

        var req = new HttpRequestMessage(HttpMethod.Post, "/api/hooks/telegram") { Content = JsonContent.Create(payload) };
        req.Headers.Add("X-Telegram-Bot-Api-Secret-Token", SecretToken);
        var res = await client.SendAsync(req);
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<KellaDbContext>();
            var action = await db.Actions.IgnoreQueryFilters().FirstAsync(a => a.Id == actId);
            // Action must NOT be approved because reply_to_message was missing!
            Assert.Equal(ActionStatus.PendingApproval, action.Status);
        }
    }

    [Fact]
    public async Task Telegram_webhook_viewer_role_approves_nothing()
    {
        var client = _factory.CreateClient();
        Guid actId;
        Guid incId;

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<KellaDbContext>();
            var org = new Organization { Name = "Org Viewer Test" };
            db.Organizations.Add(org);

            var user = new User
            {
                OrganizationId = org.Id,
                Email = "viewer@test.org",
                Name = "Viewer User",
                Role = UserRole.Viewer,
                TelegramChatId = "777777"
            };
            db.Users.Add(user);

            var server = new Server { OrganizationId = org.Id, Name = "srv-viewer" };
            db.Servers.Add(server);

            var inc = new Incident
            {
                OrganizationId = org.Id,
                ServerId = server.Id,
                Number = 5001,
                Type = "mail.outbound_spike",
                Title = "Spike Viewer",
                Status = IncidentStatus.Open
            };
            db.Incidents.Add(inc);

            var act = new KellaAction
            {
                OrganizationId = org.Id,
                IncidentId = inc.Id,
                ServerId = server.Id,
                Kind = "hold_sender",
                Params = new() { ["sender"] = "viewer_bad@bad.com" },
                Status = ActionStatus.PendingApproval,
                ExpiresAt = DateTimeOffset.UtcNow.AddHours(24)
            };
            db.Actions.Add(act);
            await db.SaveChangesAsync();

            actId = act.Id;
            incId = inc.Id;
        }

        var alert = new AlertMessage(incId, 5001, Severity.Critical, "Spike Viewer", "Body", ["hold viewer_bad@bad.com"]);
        var alertText = Kella.Infrastructure.Alerting.TelegramAlertChannel.Format(alert);

        var payload = new
        {
            update_id = 999555L,
            message = new
            {
                chat = new { id = "777777" },
                text = "1",
                reply_to_message = new { text = alertText }
            }
        };

        var req = new HttpRequestMessage(HttpMethod.Post, "/api/hooks/telegram") { Content = JsonContent.Create(payload) };
        req.Headers.Add("X-Telegram-Bot-Api-Secret-Token", SecretToken);
        var res = await client.SendAsync(req);
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<KellaDbContext>();
            var action = await db.Actions.IgnoreQueryFilters().FirstAsync(a => a.Id == actId);
            // Viewer must not be able to approve!
            Assert.Equal(ActionStatus.PendingApproval, action.Status);
        }
    }

    [Fact]
    public async Task Telegram_webhook_ack_and_status_send_reply()
    {
        var sentMessages = new List<string>();
        var testHandler = new TestHttpMessageHandler(req =>
        {
            var json = req.Content?.ReadAsStringAsync().GetAwaiter().GetResult() ?? "";
            sentMessages.Add(json);
        });

        using var customFactory = _factory.WithWebHostBuilder(b =>
        {
            b.UseSetting("Kella:Telegram:BotToken", "test-bot-token-123");
            b.ConfigureServices(services =>
            {
                services.AddSingleton(sp =>
                {
                    var cfg = sp.GetRequiredService<Microsoft.Extensions.Configuration.IConfiguration>();
                    var opts = Kella.Infrastructure.Alerting.AlertSettings.Telegram(cfg);
                    return new Kella.Infrastructure.Alerting.TelegramAlertChannel(opts, testHandler);
                });
                services.AddSingleton<Kella.Core.IAlertChannel>(sp => sp.GetRequiredService<Kella.Infrastructure.Alerting.TelegramAlertChannel>());
            });
        });

        var client = customFactory.CreateClient();
        Guid incId;

        using (var scope = customFactory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<KellaDbContext>();
            var org = new Organization { Name = "Org AckStatus Test" };
            db.Organizations.Add(org);

            var user = new User
            {
                OrganizationId = org.Id,
                Email = "ackstatus@test.org",
                Name = "AckStatus Responder",
                Role = UserRole.Responder,
                TelegramChatId = "888888"
            };
            db.Users.Add(user);

            var server = new Server { OrganizationId = org.Id, Name = "srv-ackstatus" };
            db.Servers.Add(server);

            var inc = new Incident
            {
                OrganizationId = org.Id,
                ServerId = server.Id,
                Number = 6001,
                Type = "mail.outbound_spike",
                Title = "Spike AckStatus",
                Summary = "Summary of spike",
                Status = IncidentStatus.Open
            };
            db.Incidents.Add(inc);
            await db.SaveChangesAsync();

            incId = inc.Id;
        }

        var alert = new AlertMessage(incId, 6001, Severity.Critical, "Spike AckStatus", "Body", []);
        var alertText = Kella.Infrastructure.Alerting.TelegramAlertChannel.Format(alert);

        // 1. Send "ack"
        var ackPayload = new
        {
            update_id = 111001L,
            message = new
            {
                chat = new { id = "888888" },
                text = "ack",
                reply_to_message = new { text = alertText }
            }
        };
        var ackReq = new HttpRequestMessage(HttpMethod.Post, "/api/hooks/telegram") { Content = JsonContent.Create(ackPayload) };
        ackReq.Headers.Add("X-Telegram-Bot-Api-Secret-Token", SecretToken);
        var ackRes = await client.SendAsync(ackReq);
        Assert.Equal(HttpStatusCode.OK, ackRes.StatusCode);

        // Assert incident acknowledged in DB
        using (var scope = customFactory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<KellaDbContext>();
            var incident = await db.Incidents.IgnoreQueryFilters().FirstAsync(i => i.Id == incId);
            Assert.NotNull(incident.AcknowledgedAt);
            Assert.Equal("telegram:ackstatus@test.org", incident.AcknowledgedBy);
        }

        // Assert ack reply was sent
        Assert.Contains(sentMessages, msg => msg.Contains("Acknowledged INC-6001"));

        // 2. Send "status"
        var statusPayload = new
        {
            update_id = 111002L,
            message = new
            {
                chat = new { id = "888888" },
                text = "status",
                reply_to_message = new { text = alertText }
            }
        };
        var statusReq = new HttpRequestMessage(HttpMethod.Post, "/api/hooks/telegram") { Content = JsonContent.Create(statusPayload) };
        statusReq.Headers.Add("X-Telegram-Bot-Api-Secret-Token", SecretToken);
        var statusRes = await client.SendAsync(statusReq);
        Assert.Equal(HttpStatusCode.OK, statusRes.StatusCode);

        // Assert status reply was sent
        Assert.Contains(sentMessages, msg => msg.Contains("INC-6001") && msg.Contains("Summary of spike"));
    }

    [Fact]
    public async Task Telegram_webhook_reply_1_twice_approves_only_first_action_and_invalid_N_gets_reply()
    {
        var sentMessages = new List<string>();
        var handler = new TestHttpMessageHandler(req =>
        {
            if (req.Content is JsonContent json)
            {
                var body = req.Content.ReadAsStringAsync().Result;
                sentMessages.Add(body);
            }
        });

        using var customFactory = _factory.WithWebHostBuilder(b =>
        {
            b.ConfigureServices(services =>
            {
                services.AddSingleton(new Kella.Infrastructure.Alerting.TelegramAlertChannel(
                    new Kella.Infrastructure.Alerting.TelegramOptions { BotToken = "test-token", ApiBase = "http://telegram.test" },
                    handler));
            });
        });

        var client = customFactory.CreateClient();
        Guid incId;
        Guid act1Id;
        Guid act2Id;
        long alertMessageId = 777L;

        using (var scope = customFactory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<KellaDbContext>();
            var org = new Organization { Name = "Org Stable Options Test" };
            db.Organizations.Add(org);

            var user = new User
            {
                OrganizationId = org.Id,
                Email = "stable_options@test.org",
                Name = "Stable User",
                Role = UserRole.Responder,
                TelegramChatId = "999999"
            };
            db.Users.Add(user);

            var server = new Server { OrganizationId = org.Id, Name = "srv-stable" };
            db.Servers.Add(server);

            var inc = new Incident
            {
                OrganizationId = org.Id,
                ServerId = server.Id,
                Number = 7001,
                Type = "mail.outbound_spike",
                Title = "Spike Stable Options",
                Status = IncidentStatus.Open
            };
            db.Incidents.Add(inc);

            var act1 = new KellaAction
            {
                OrganizationId = org.Id,
                IncidentId = inc.Id,
                ServerId = server.Id,
                Kind = "hold_sender",
                Params = new() { ["sender"] = "user1@test.org" },
                Status = ActionStatus.PendingApproval,
                CreatedAt = DateTimeOffset.UtcNow.AddMinutes(-5),
                ExpiresAt = DateTimeOffset.UtcNow.AddHours(1)
            };
            var act2 = new KellaAction
            {
                OrganizationId = org.Id,
                IncidentId = inc.Id,
                ServerId = server.Id,
                Kind = "hold_sender",
                Params = new() { ["sender"] = "user2@test.org" },
                Status = ActionStatus.PendingApproval,
                CreatedAt = DateTimeOffset.UtcNow.AddMinutes(-4),
                ExpiresAt = DateTimeOffset.UtcNow.AddHours(1)
            };
            db.Actions.AddRange(act1, act2);

            var delivery = new AlertDelivery
            {
                OrganizationId = org.Id,
                IncidentId = inc.Id,
                Channel = "telegram",
                Recipient = "stable_options@test.org",
                Status = "sent",
                MessageId = alertMessageId,
                Severity = Severity.Critical,
                ActionIds = [act1.Id, act2.Id]
            };
            db.AlertDeliveries.Add(delivery);

            await db.SaveChangesAsync();

            incId = inc.Id;
            act1Id = act1.Id;
            act2Id = act2.Id;
        }

        var alert = new AlertMessage(incId, 7001, Severity.Critical, "Spike Stable Options", "Body", ["hold user1", "hold user2"]);
        var alertText = Kella.Infrastructure.Alerting.TelegramAlertChannel.Format(alert);

        // 1. First reply "1" -> approves action 1
        var payload1 = new
        {
            update_id = 90001L,
            message = new
            {
                chat = new { id = "999999" },
                text = "1",
                reply_to_message = new
                {
                    message_id = alertMessageId,
                    text = alertText
                }
            }
        };
        var req1 = new HttpRequestMessage(HttpMethod.Post, "/api/hooks/telegram") { Content = JsonContent.Create(payload1) };
        req1.Headers.Add("X-Telegram-Bot-Api-Secret-Token", SecretToken);
        var res1 = await client.SendAsync(req1);
        Assert.Equal(HttpStatusCode.OK, res1.StatusCode);

        using (var scope = customFactory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<KellaDbContext>();
            var action1 = await db.Actions.IgnoreQueryFilters().FirstAsync(a => a.Id == act1Id);
            Assert.Equal(ActionStatus.Queued, action1.Status);
        }

        // 2. Second reply "1" -> MUST NOT approve action 2! Must reply "No pending action 1"
        var payload2 = new
        {
            update_id = 90002L,
            message = new
            {
                chat = new { id = "999999" },
                text = "1",
                reply_to_message = new
                {
                    message_id = alertMessageId,
                    text = alertText
                }
            }
        };
        var req2 = new HttpRequestMessage(HttpMethod.Post, "/api/hooks/telegram") { Content = JsonContent.Create(payload2) };
        req2.Headers.Add("X-Telegram-Bot-Api-Secret-Token", SecretToken);
        var res2 = await client.SendAsync(req2);
        Assert.Equal(HttpStatusCode.OK, res2.StatusCode);

        using (var scope = customFactory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<KellaDbContext>();
            var action2 = await db.Actions.IgnoreQueryFilters().FirstAsync(a => a.Id == act2Id);
            // Action 2 MUST NOT be approved! It must remain PendingApproval!
            Assert.Equal(ActionStatus.PendingApproval, action2.Status);
        }
        Assert.Contains(sentMessages, msg => msg.Contains("No pending action 1"));

        // 3. Reply "99" (invalid N) -> replies "No pending action 99"
        var payload99 = new
        {
            update_id = 90003L,
            message = new
            {
                chat = new { id = "999999" },
                text = "99",
                reply_to_message = new
                {
                    message_id = alertMessageId,
                    text = alertText
                }
            }
        };
        var req99 = new HttpRequestMessage(HttpMethod.Post, "/api/hooks/telegram") { Content = JsonContent.Create(payload99) };
        req99.Headers.Add("X-Telegram-Bot-Api-Secret-Token", SecretToken);
        var res99 = await client.SendAsync(req99);
        Assert.Equal(HttpStatusCode.OK, res99.StatusCode);
        Assert.Contains(sentMessages, msg => msg.Contains("No pending action 99"));
    }
}

public class TestHttpMessageHandler(Action<HttpRequestMessage> onRequest) : HttpMessageHandler
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        onRequest(request);
        return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("{\"ok\":true}")
        });
    }
}
