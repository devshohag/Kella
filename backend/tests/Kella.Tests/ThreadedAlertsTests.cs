using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Kella.Core;
using Kella.Core.Domain;
using Kella.Infrastructure;
using Kella.Infrastructure.Alerting;
using Kella.Infrastructure.Data;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Xunit;

namespace Kella.Tests;

public class ThreadedAlertsTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;

    public ThreadedAlertsTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory.WithWebHostBuilder(b =>
        {
            b.UseEnvironment("Development");
            b.UseSetting("ConnectionStrings:Postgres", "");
            b.UseSetting("Kella:RunPipelineInApi", "true");
            b.UseSetting("Kella:Jwt:Key", "kella-testing-only-signing-key-32b");
            b.UseSetting("Kella:Seed:OwnerPassword", "test-owner-password");
            b.UseSetting("Kella:Telegram:BotToken", "test-bot-token");
        });
    }

    private sealed class MockTelegramHandler : HttpMessageHandler
    {
        public List<JsonDocument> SentRequests { get; } = [];
        public long NextMessageId { get; set; } = 1001;

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var bodyStream = await request.Content!.ReadAsStreamAsync(cancellationToken);
            var doc = await JsonDocument.ParseAsync(bodyStream, cancellationToken: cancellationToken);
            SentRequests.Add(doc);

            var resp = new
            {
                ok = true,
                result = new
                {
                    message_id = NextMessageId++,
                    date = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
                }
            };
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(JsonSerializer.Serialize(resp), System.Text.Encoding.UTF8, "application/json")
            };
        }
    }

    [Fact]
    public async Task Join_with_severity_increase_sends_reply_with_stored_message_id_and_otherwise_sends_nothing()
    {
        var mockHandler = new MockTelegramHandler();

        using var factory = _factory.WithWebHostBuilder(b =>
        {
            b.ConfigureServices(services =>
            {
                services.RemoveAll<IAlertChannel>();
                services.RemoveAll<TelegramAlertChannel>();
                var options = new TelegramOptions
                {
                    BotToken = "test-token",
                    ApiBase = "https://api.telegram.org",
                };
                services.AddSingleton<IAlertChannel>(new TelegramAlertChannel(options, mockHandler));
            });
        });

        using var scope = factory.Services.CreateScope();
        var orgId = Guid.NewGuid();
        scope.ServiceProvider.GetRequiredService<OrgContext>().Set(orgId);
        var db = scope.ServiceProvider.GetRequiredService<KellaDbContext>();
        var router = scope.ServiceProvider.GetRequiredService<IAlertRouter>();

        var org = new Organization { Id = orgId, Name = "Threaded Org" };
        db.Organizations.Add(org);
        var user = new User
        {
            OrganizationId = orgId,
            Email = "admin@threaded.org",
            Name = "Admin",
            TelegramChatId = "12345678",
            Role = UserRole.Admin,
        };
        db.Users.Add(user);

        var server = new Server { OrganizationId = orgId, Name = "srv-threaded" };
        db.Servers.Add(server);

        var incident = new Incident
        {
            OrganizationId = orgId,
            Number = 101,
            ServerId = server.Id,
            Type = "mail",
            Severity = Severity.Warning,
            Title = "Initial mail warning",
            Summary = "Warning details",
            OpenedAt = DateTimeOffset.UtcNow,
        };
        db.Incidents.Add(incident);
        await db.SaveChangesAsync();

        // 1. Initial route: sends alert without reply_to_message_id
        await router.RouteAsync(incident, default);

        Assert.Single(mockHandler.SentRequests);
        var initialReq = mockHandler.SentRequests[0];
        Assert.False(initialReq.RootElement.TryGetProperty("reply_to_message_id", out _));

        var deliveries = await db.AlertDeliveries.IgnoreQueryFilters()
            .Where(d => d.IncidentId == incident.Id && d.Channel == "telegram")
            .ToListAsync();
        Assert.Single(deliveries);
        // Stored message_id should be 1001
        Assert.Equal(1001, deliveries[0].MessageId);

        // 2. Join with severity increase: Warning -> Critical
        incident.Severity = Severity.Critical;
        incident.Title = "Escalated mail critical";
        await db.SaveChangesAsync();

        await router.RouteAsync(incident, default);

        // Must have sent a second message to Telegram
        Assert.Equal(2, mockHandler.SentRequests.Count);
        var secondReq = mockHandler.SentRequests[1];
        Assert.True(secondReq.RootElement.TryGetProperty("reply_to_message_id", out var replyToProp));
        Assert.Equal(1001, replyToProp.GetInt64());

        // 3. Join without severity increase or new approval action: sends NOTHING
        await router.RouteAsync(incident, default);

        // Still only 2 requests sent
        Assert.Equal(2, mockHandler.SentRequests.Count);
    }
}
