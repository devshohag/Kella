using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
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

    [Fact]
    public void CommandSigner_throws_in_testing_environment_with_all_zero_key()
    {
        var config = new Microsoft.Extensions.Configuration.ConfigurationBuilder()
            .AddInMemoryCollection(new System.Collections.Generic.Dictionary<string, string?>
            {
                ["Kella:Commands:PrivateKey"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
            })
            .Build();

        var env = new TestHostEnvironment { EnvironmentName = "Testing" };

        // Before fix: env.IsEnvironment("Testing") is treated as dev, so it does NOT throw!
        // After fix: only IsDevelopment() counts as dev, so this MUST throw!
        var ex = Assert.Throws<InvalidOperationException>(() => new Kella.Infrastructure.Security.CommandSigner(config, env));
        Assert.Contains("cannot be the all-zero seed", ex.Message);
    }

    [Fact]
    public void CommandSigner_throws_in_testing_environment_when_key_is_missing()
    {
        var config = new ConfigurationBuilder().Build();
        var env = new TestHostEnvironment { EnvironmentName = "Testing" };
        var ex = Assert.Throws<InvalidOperationException>(() => new Kella.Infrastructure.Security.CommandSigner(config, env));
        Assert.Contains("Kella:Commands:PrivateKey is required", ex.Message);
    }

    [Fact]
    public async System.Threading.Tasks.Task Webhook_returns_503_in_testing_environment_when_secret_token_is_missing()
    {
        // 32-byte non-zero valid seed for CommandSigner
        var validKey = Convert.ToBase64String(new byte[32].Select((_, i) => (byte)(i + 1)).ToArray());

        using var factory = new WebApplicationFactory<Program>().WithWebHostBuilder(b =>
        {
            b.UseEnvironment("Testing");
            b.UseSetting("ConnectionStrings:Postgres", "");
            b.UseSetting("Kella:Jwt:Key", "testing-jwt-key-minimum-32-bytes!!");
            b.UseSetting("Kella:Seed:OwnerEmail", "owner@example.com");
            b.UseSetting("Kella:Seed:OwnerPassword", "owner-secure-password-123");
            b.UseSetting("Kella:Commands:PrivateKey", validKey);
            b.UseSetting("Kella:Telegram:WebhookSecretToken", "");
        });

        var client = factory.CreateClient();
        var res = await client.PostAsync("/api/hooks/telegram", new System.Net.Http.StringContent("{}", System.Text.Encoding.UTF8, "application/json"));
        Assert.Equal(System.Net.HttpStatusCode.ServiceUnavailable, res.StatusCode);
    }
}

public class TestHostEnvironment : Microsoft.Extensions.Hosting.IHostEnvironment
{
    public string EnvironmentName { get; set; } = "Testing";
    public string ApplicationName { get; set; } = "Kella.Tests";
    public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
    public Microsoft.Extensions.FileProviders.IFileProvider ContentRootFileProvider { get; set; } = new Microsoft.Extensions.FileProviders.NullFileProvider();
}
