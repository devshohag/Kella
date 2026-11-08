using System;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace Kella.Tests;

public class SecurityConfigTests
{
    [Fact]
    public void Startup_throws_in_production_when_command_key_is_missing()
    {
        using var factory = new WebApplicationFactory<Program>().WithWebHostBuilder(b =>
        {
            b.UseEnvironment("Production");
            b.UseSetting("ConnectionStrings:Postgres", "");
            b.UseSetting("Kella:Jwt:Key", "production-test-jwt-key-minimum-32-bytes!");
            b.UseSetting("Kella:Seed:OwnerEmail", "owner@example.com");
            b.UseSetting("Kella:Seed:OwnerPassword", "owner-secure-password-123");
            b.UseSetting("Kella:Telegram:WebhookSecretToken", "secret-token-test");
            b.UseSetting("Kella:Commands:PrivateKey", "");
        });

        var ex = Assert.ThrowsAny<Exception>(() => factory.CreateClient());
        Assert.Contains("Kella:Commands:PrivateKey", ex.ToString());
    }

    [Fact]
    public void Startup_throws_in_production_when_command_key_is_all_zero()
    {
        using var factory = new WebApplicationFactory<Program>().WithWebHostBuilder(b =>
        {
            b.UseEnvironment("Production");
            b.UseSetting("ConnectionStrings:Postgres", "");
            b.UseSetting("Kella:Jwt:Key", "production-test-jwt-key-minimum-32-bytes!");
            b.UseSetting("Kella:Seed:OwnerEmail", "owner@example.com");
            b.UseSetting("Kella:Seed:OwnerPassword", "owner-secure-password-123");
            b.UseSetting("Kella:Telegram:WebhookSecretToken", "secret-token-test");
            b.UseSetting("Kella:Commands:PrivateKey", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
        });

        var ex = Assert.ThrowsAny<Exception>(() => factory.CreateClient());
        Assert.Contains("all-zero seed", ex.ToString());
    }
}
