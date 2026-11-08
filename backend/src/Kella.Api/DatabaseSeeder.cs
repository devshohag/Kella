using Kella.Core.Domain;
using Kella.Infrastructure;
using Kella.Infrastructure.Data;
using Kella.Infrastructure.Security;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace Kella.Api;

/// <summary>Holds the demo organization used when development login is bypassed.</summary>
public sealed class DevOrgState
{
    public Guid OrganizationId { get; set; }
}

/// <summary>
/// Applies EF Core migrations and seeds the first organization + owner (SPEC §17 Phase 0).
/// Development/Testing also get a demo organization, tenants and a reusable enrollment key.
/// </summary>
public static class DatabaseSeeder
{
    public const string DevEnrollmentKey = "kella_dev_local_only";

    public static async Task InitializeAsync(WebApplication app, bool devBypass)
    {
        using var scope = app.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<KellaDbContext>();

        if (db.Database.IsRelational()) await db.Database.MigrateAsync();
        else await db.Database.EnsureCreatedAsync();

        var hasher = scope.ServiceProvider.GetRequiredService<IPasswordHasher<User>>();
        if (app.Environment.IsDevelopment() || app.Environment.IsEnvironment("Testing"))
        {
            var state = scope.ServiceProvider.GetRequiredService<DevOrgState>();
            await SeedDevelopmentAsync(db, app.Configuration, hasher, state, devBypass);
        }
        else
        {
            await SeedProductionAsync(db, app.Configuration, hasher);
        }
    }

    private static async Task SeedDevelopmentAsync(
        KellaDbContext db, IConfiguration config, IPasswordHasher<User> hasher, DevOrgState state, bool devBypass)
    {
        var orgName = config["Kella:Seed:OrganizationName"] ?? "Northwind Hosting (dev)";
        var org = await db.Organizations.FirstOrDefaultAsync(o => o.Name == orgName);
        if (org is not null)
        {
            if (devBypass) state.OrganizationId = org.Id;
            return;
        }

        var email = (config["Kella:Seed:OwnerEmail"] ?? "owner@example.com").Trim().ToLowerInvariant();
        var password = config["Kella:Seed:OwnerPassword"]
            ?? throw new InvalidOperationException("Kella:Seed:OwnerPassword is required to seed the development owner.");

        org = new Organization { Name = orgName, Plan = "business" };
        var owner = new User
        {
            OrganizationId = org.Id,
            Email = email,
            Name = "Dev Owner",
            Role = UserRole.Owner,
        };
        owner.PasswordHash = hasher.HashPassword(owner, password);

        db.Organizations.Add(org);
        db.Users.Add(owner);
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

        if (devBypass) state.OrganizationId = org.Id;
    }

    private static async Task SeedProductionAsync(KellaDbContext db, IConfiguration config, IPasswordHasher<User> hasher)
    {
        if (await db.Organizations.AnyAsync()) return;

        var orgName = config["Kella:Seed:OrganizationName"] ?? "Kella";
        var email = config["Kella:Seed:OwnerEmail"]?.Trim().ToLowerInvariant();
        var password = config["Kella:Seed:OwnerPassword"];
        if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(password))
            throw new InvalidOperationException(
                "No organization exists. Set Kella:Seed:OwnerEmail and Kella:Seed:OwnerPassword (KELLA__SEED__*) to seed the first owner.");

        var org = new Organization { Name = orgName };
        var owner = new User
        {
            OrganizationId = org.Id,
            Email = email,
            Name = "Owner",
            Role = UserRole.Owner,
        };
        owner.PasswordHash = hasher.HashPassword(owner, password);

        db.Organizations.Add(org);
        db.Users.Add(owner);
        await db.SaveChangesAsync();
    }

    /// <summary>
    /// Development only: lets dashboard requests without a session run as the demo organization.
    /// Requests authenticated with a JWT keep their own organization.
    /// </summary>
    public static IApplicationBuilder UseDevOrg(this IApplicationBuilder app) =>
        app.Use(async (ctx, next) =>
        {
            var isDevRequest = ctx.Request.Path.StartsWithSegments("/api")
                && !ctx.Request.Path.StartsWithSegments("/api/agent")
                && !ctx.Request.Path.StartsWithSegments("/api/auth")
                && !ctx.Request.Path.StartsWithSegments("/api/hooks");
            if (isDevRequest && ctx.User.Identity?.IsAuthenticated != true)
            {
                var state = ctx.RequestServices.GetRequiredService<DevOrgState>();
                if (state.OrganizationId != Guid.Empty)
                    ctx.RequestServices.GetRequiredService<OrgContext>().Set(state.OrganizationId);
            }
            await next();
        });
}
