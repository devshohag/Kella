using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Shield.Core;
using Shield.Core.Rules;
using Shield.Infrastructure.Data;
using Shield.Infrastructure.Pipeline;

namespace Shield.Infrastructure;

public static class DependencyInjection
{
    /// <summary>Database, org context, event bus and built-in rules.</summary>
    public static IServiceCollection AddShieldInfrastructure(this IServiceCollection services, IConfiguration config)
    {
        services.AddScoped<OrgContext>();
        services.AddScoped<IOrgContext>(sp => sp.GetRequiredService<OrgContext>());

        var cs = config.GetConnectionString("Postgres");
        services.AddDbContext<ShieldDbContext>(o =>
        {
            if (string.IsNullOrWhiteSpace(cs)) o.UseInMemoryDatabase("shield-dev");
            else o.UseNpgsql(cs);
        });

        services.AddSingleton<IEventBus, InProcessEventBus>();

        // Built-in rules (SPEC §9). Add new rules here.
        services.AddSingleton<IRule, SshBruteForceRule>();
        services.AddSingleton<IRule, MailBruteForceIpRule>();
        return services;
    }

    /// <summary>Workers that consume the event bus. Hosted by Shield.Worker, or by the API in single-process dev mode.</summary>
    public static IServiceCollection AddShieldPipeline(this IServiceCollection services)
    {
        services.AddHostedService<RuleEngineService>();
        return services;
    }
}
