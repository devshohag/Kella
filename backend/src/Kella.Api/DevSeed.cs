using Microsoft.EntityFrameworkCore;
using Kella.Core.Domain;
using Kella.Infrastructure;
using Kella.Infrastructure.Data;
using Kella.Infrastructure.Security;

namespace Kella.Api;

/// <summary>
/// Development only: creates a demo organization and a reusable enrollment key, and lets dashboard
/// requests run as that organization without login. Never active outside the Development environment.
/// TODO(Phase 0): replace DevOrgMiddleware with real login (ASP.NET Identity + JWT cookie, SPEC §5, §16).
/// </summary>
public static class DevSeed
{
    public const string DevEnrollmentKey = "kella_dev_local_only";
    public static Guid DevOrgId { get; private set; }

    public static async Task RunAsync(IServiceProvider services)
    {
        using var scope = services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<KellaDbContext>();
        await db.Database.EnsureCreatedAsync(); // TODO(Phase 0): replace with migrations

        var existing = await db.Organizations.FirstOrDefaultAsync(o => o.Name == "Northwind Hosting (dev)");
        if (existing is not null) { DevOrgId = existing.Id; return; }

        var org = new Organization { Name = "Northwind Hosting (dev)", Plan = "business" };
        DevOrgId = org.Id;
        db.Organizations.Add(org);
        db.Users.Add(new User { OrganizationId = org.Id, Email = "owner@example.com", Name = "Dev Owner", Role = UserRole.Owner });
        db.EnrollmentKeys.Add(new EnrollmentKey
        {
            OrganizationId = org.Id,
            KeyHash = Tokens.Hash(DevEnrollmentKey),
            ExpiresAt = DateTimeOffset.UtcNow.AddYears(1),
            UsesLeft = 1000,
        });
        db.Tenants.Add(new Tenant { OrganizationId = org.Id, Name = "Rahman Traders" });
        db.Tenants.Add(new Tenant { OrganizationId = org.Id, Name = "Deshi Mart" });
        await db.SaveChangesAsync();
    }

    public static IApplicationBuilder UseDevOrg(this IApplicationBuilder app) =>
        app.Use(async (ctx, next) =>
        {
            if (ctx.Request.Path.StartsWithSegments("/api") && !ctx.Request.Path.StartsWithSegments("/api/agent"))
                ctx.RequestServices.GetRequiredService<OrgContext>().Set(DevOrgId);
            await next();
        });
}
