using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Kella.Api;
using Kella.Api.Endpoints;

namespace Kella.Tests;

public class AgentApiTests(WebApplicationFactory<Program> factory) : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory = factory.WithWebHostBuilder(b =>
    {
        b.UseEnvironment("Testing");
        b.UseSetting("ConnectionStrings:Postgres", ""); // in-memory database
        b.UseSetting("Kella:RunPipelineInApi", "true");
        b.UseSetting("Kella:Jwt:Key", "kella-testing-only-signing-key-32b");
        b.UseSetting("Kella:Jwt:SecureCookies", "false");
        b.UseSetting("Kella:Seed:OwnerPassword", "test-owner-password");
    });

    private async Task<(HttpClient client, EnrollResponse enrolled)> EnrollAsync()
    {
        var client = _factory.CreateClient();
        var res = await client.PostAsJsonAsync("/api/agent/enroll",
            new EnrollRequest(DatabaseSeeder.DevEnrollmentKey, $"test-{Guid.NewGuid():N}", "Ubuntu 24.04", 4, 8192, "203.0.113.10", "0.1.0"));
        res.EnsureSuccessStatusCode();
        var enrolled = (await res.Content.ReadFromJsonAsync<EnrollResponse>())!;
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", enrolled.AgentToken);
        return (client, enrolled);
    }

    [Fact]
    public async Task Enroll_rejects_unknown_key()
    {
        var client = _factory.CreateClient();
        var res = await client.PostAsJsonAsync("/api/agent/enroll",
            new EnrollRequest("kella_wrong", "h", "linux", 1, 512, null, "0.1.0"));
        Assert.Equal(HttpStatusCode.Unauthorized, res.StatusCode);
    }

    [Fact]
    public async Task Agent_endpoints_require_token()
    {
        var client = _factory.CreateClient();
        var res = await client.GetAsync("/api/agent/commands");
        Assert.Equal(HttpStatusCode.Unauthorized, res.StatusCode);
    }

    [Fact]
    public async Task Ssh_bruteforce_events_produce_a_block_ip_command()
    {
        var (client, enrolled) = await EnrollAsync();
        var now = DateTimeOffset.UtcNow;
        var events = Enumerable.Range(0, 12).Select(i => new AgentEventDto(
            Guid.NewGuid().ToString(), now.AddSeconds(i), "server", "server.ssh_auth_failed", "info",
            "198.51.100.7", new() { ["user"] = "root" })).ToList();

        var post = await client.PostAsJsonAsync("/api/agent/events",
            new EventBatch("0.1.0", enrolled.ServerId, now, events));
        post.EnsureSuccessStatusCode();

        // Rule engine runs asynchronously; long-poll for the resulting command.
        CommandDto[] cmds = [];
        for (var attempt = 0; attempt < 10 && cmds.Length == 0; attempt++)
            cmds = (await client.GetFromJsonAsync<CommandDto[]>("/api/agent/commands?wait=1"))!;

        var cmd = Assert.Single(cmds);
        Assert.Equal("block_ip", cmd.Kind);
        Assert.Equal("198.51.100.7", cmd.Params["ip"]);

        var ack = await client.PostAsJsonAsync($"/api/agent/commands/{cmd.Id}/ack", new CommandAck(true, "added to kella_block"));
        Assert.Equal(HttpStatusCode.NoContent, ack.StatusCode);
    }
}
