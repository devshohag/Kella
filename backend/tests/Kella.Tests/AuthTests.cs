using System.Net;
using System.Net.Http.Json;
using Kella.Api;
using Kella.Api.Endpoints;
using Kella.Core.Auth;
using Kella.Core.Domain;
using Kella.Infrastructure.Data;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Kella.Tests;

public class AuthTests(WebApplicationFactory<Program> factory) : IClassFixture<WebApplicationFactory<Program>>
{
    private const string Password = "correct-horse-battery-staple";

    private readonly WebApplicationFactory<Program> _factory = factory.WithWebHostBuilder(b =>
    {
        b.UseEnvironment("Testing");
        b.UseSetting("ConnectionStrings:Postgres", ""); // in-memory database
        b.UseSetting("Kella:Jwt:Key", "kella-testing-only-signing-key-32b");
        b.UseSetting("Kella:Jwt:SecureCookies", "false");
        b.UseSetting("Kella:Seed:OwnerPassword", "test-owner-password");
        b.UseSetting("Kella:DevOrg:Enabled", "false"); // exercise the real login path
        b.UseSetting("Kella:RateLimits:AuthPermitLimit", "1000"); // tests share one client address
    });

    private HttpClient Client() => _factory.CreateClient();

    private async Task<Guid> SeededOrgIdAsync()
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<KellaDbContext>();
        return await db.Organizations.OrderBy(o => o.CreatedAt).Select(o => o.Id).FirstAsync();
    }

    private async Task<User> CreateUserAsync(UserRole role, Guid? organizationId = null, string? totpSecret = null)
    {
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<KellaDbContext>();
        var user = new User
        {
            OrganizationId = organizationId ?? await SeededOrgIdAsync(),
            Email = $"user-{Guid.NewGuid():N}@test.local",
            Name = "Test User",
            Role = role,
            TotpSecret = totpSecret,
        };
        user.PasswordHash = scope.ServiceProvider.GetRequiredService<IPasswordHasher<User>>()
            .HashPassword(user, Password);
        db.Users.Add(user);
        await db.SaveChangesAsync();
        return user;
    }

    private static async Task<HttpResponseMessage> LoginAsync(HttpClient client, string email, string? password = null, string? code = null) =>
        await client.PostAsJsonAsync("/api/auth/login", new LoginRequest(email, password ?? Password, code));

    [Fact]
    public async Task Owner_first_login_requires_totp_setup_then_issues_a_session()
    {
        var owner = await CreateUserAsync(UserRole.Owner);
        var client = Client();

        var login = await LoginAsync(client, owner.Email);
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        var first = (await login.Content.ReadFromJsonAsync<LoginResponse>())!;
        Assert.True(first.TotpSetupRequired);
        Assert.False(string.IsNullOrEmpty(first.SetupToken));
        Assert.Null(first.User);

        var setup = await client.PostAsJsonAsync("/api/auth/totp/setup", new TotpSetupRequest(first.SetupToken!));
        setup.EnsureSuccessStatusCode();
        var totp = (await setup.Content.ReadFromJsonAsync<TotpSetupResponse>())!;
        Assert.NotEmpty(totp.Secret);
        Assert.StartsWith("otpauth://totp/", totp.OtpauthUri);

        var enable = await client.PostAsJsonAsync("/api/auth/totp/enable",
            new TotpEnableRequest(first.SetupToken!, Totp.Code(totp.Secret, DateTimeOffset.UtcNow)));
        enable.EnsureSuccessStatusCode();
        var enabled = (await enable.Content.ReadFromJsonAsync<AuthUserDto>())!;
        Assert.Equal(owner.Email, enabled.Email);
        Assert.Equal("Owner", enabled.Role);

        // Cookies from the enable response authenticate dashboard calls.
        var me = await client.GetFromJsonAsync<AuthUserDto>("/api/auth/me");
        Assert.Equal(owner.Email, me!.Email);

        // A later login must present the second factor.
        var secondClient = Client();
        var second = await LoginAsync(secondClient, owner.Email);
        Assert.Equal(HttpStatusCode.Unauthorized, second.StatusCode);

        var withCode = await LoginAsync(secondClient, owner.Email,
            code: Totp.Code(totp.Secret, DateTimeOffset.UtcNow));
        Assert.Equal(HttpStatusCode.OK, withCode.StatusCode);
        var session = (await withCode.Content.ReadFromJsonAsync<LoginResponse>())!;
        Assert.False(session.TotpSetupRequired);
        Assert.Equal(owner.Email, session.User!.Email);
    }

    [Fact]
    public async Task Five_wrong_passwords_lock_the_account()
    {
        var user = await CreateUserAsync(UserRole.Viewer);
        var client = Client();

        for (var attempt = 1; attempt <= 5; attempt++)
        {
            var failed = await LoginAsync(client, user.Email, "not-the-password");
            Assert.Equal(HttpStatusCode.Unauthorized, failed.StatusCode);
        }

        // Even the correct password is refused while the lockout is active.
        var locked = await LoginAsync(client, user.Email);
        Assert.Equal((HttpStatusCode)423, locked.StatusCode);
    }

    [Fact]
    public async Task Refresh_rotates_the_session_and_logout_clears_it()
    {
        var user = await CreateUserAsync(UserRole.Viewer);
        var client = Client();

        var login = await LoginAsync(client, user.Email);
        login.EnsureSuccessStatusCode();
        Assert.Equal(user.Email, (await client.GetFromJsonAsync<AuthUserDto>("/api/auth/me"))!.Email);

        var refresh = await client.PostAsync("/api/auth/refresh", null);
        Assert.Equal(HttpStatusCode.OK, refresh.StatusCode);

        var logout = await client.PostAsync("/api/auth/logout", null);
        Assert.Equal(HttpStatusCode.NoContent, logout.StatusCode);

        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/auth/me")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.PostAsync("/api/auth/refresh", null)).StatusCode);
    }

    [Fact]
    public async Task Rows_from_another_organization_are_invisible()
    {
        var orgA = await SeededOrgIdAsync();
        var user = await CreateUserAsync(UserRole.Viewer, orgA);
        var client = Client();

        var otherOrg = new Organization { Name = $"Other {Guid.NewGuid():N}" };
        var otherServer = new Server
        {
            OrganizationId = otherOrg.Id, Name = "other-org-server", Hostname = "other", Status = ServerStatus.Online,
        };
        var otherIncident = new Incident
        {
            OrganizationId = otherOrg.Id, Number = 2001, Type = "ssh.bruteforce", Severity = Severity.Critical,
            Title = "Other org incident",
        };
        var otherAction = new KellaAction
        {
            OrganizationId = otherOrg.Id, ServerId = otherServer.Id, Kind = "block_ip",
            Mode = ActionMode.Approval, Status = ActionStatus.PendingApproval, ExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
        };
        var ownServer = new Server
        {
            OrganizationId = orgA, Name = "own-server", Hostname = "own", Status = ServerStatus.Online,
        };

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<KellaDbContext>();
            db.Organizations.Add(otherOrg);
            db.Servers.AddRange(otherServer, ownServer);
            db.Incidents.Add(otherIncident);
            db.Actions.Add(otherAction);
            await db.SaveChangesAsync();
        }

        (await LoginAsync(client, user.Email)).EnsureSuccessStatusCode();

        var servers = await client.GetFromJsonAsync<ServerListItem[]>("/api/servers");
        Assert.Contains(servers!, s => s.Id == ownServer.Id);
        Assert.DoesNotContain(servers!, s => s.Id == otherServer.Id);

        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync($"/api/incidents/{otherIncident.Id}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await client.PostAsync($"/api/actions/{otherAction.Id}/approve", null)).StatusCode);

        var overview = await client.GetFromJsonAsync<OverviewDto>("/api/overview");
        Assert.Equal(1, overview!.ServersTotal); // cannot see the other organization's server
        Assert.DoesNotContain(overview.ActiveIncidents, i => i.Id == otherIncident.Id);
    }
}
