using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Kella.Core;
using Kella.Core.Rules;
using Kella.Infrastructure.Data;
using Kella.Infrastructure.Pipeline;
using Kella.Infrastructure.Security;

namespace Kella.Infrastructure;

public static class DependencyInjection
{
    /// <summary>Database, org context, event bus and built-in rules.</summary>
    public static IServiceCollection AddKellaInfrastructure(this IServiceCollection services, IConfiguration config)
    {
        services.AddScoped<OrgContext>();
        services.AddScoped<IOrgContext>(sp => sp.GetRequiredService<OrgContext>());

        var cs = config.GetConnectionString("Postgres");
        // Unique name per host: EF's in-memory store is process-wide, so a fixed name would leak rows
        // between test hosts (and between parallel test classes).
        var inMemoryName = $"kella-{Guid.NewGuid():N}";
        services.AddDbContext<KellaDbContext>(o =>
        {
            if (string.IsNullOrWhiteSpace(cs)) o.UseInMemoryDatabase(inMemoryName);
            else o.UseNpgsql(cs);
        });

        services.AddSingleton<IEventBus, InProcessEventBus>();
        services.AddSingleton<CommandSigner>();

        // Built-in rules (SPEC §9). Add new rules here.
        services.AddSingleton<IRule, SshBruteForceRule>();
        services.AddSingleton<IRule, MailBruteForceIpRule>();
        services.AddSingleton<IRule, MailOutboundSpikeRule>();
        services.AddSingleton<IRule, MailAccountTakeoverRule>();
        return services;
    }

    /// <summary>Workers that consume the event bus. Hosted by Kella.Worker, or by the API in single-process dev mode.</summary>
    public static IServiceCollection AddKellaPipeline(this IServiceCollection services)
    {
        services.AddHostedService<RuleEngineService>();
        services.AddHostedService<IpReputationService>();
        return services;
    }
}
