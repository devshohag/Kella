using System.Linq.Expressions;
using Microsoft.EntityFrameworkCore;
using Kella.Core;
using Kella.Core.Domain;

namespace Kella.Infrastructure.Data;

/// <summary>
/// Every <see cref="IOrgScoped"/> entity is filtered to the current organization.
/// Rows are invisible when no organization is set (e.g. anonymous requests).
/// </summary>
public sealed class KellaDbContext(DbContextOptions<KellaDbContext> options, IOrgContext org) : DbContext(options)
{
    private Guid? CurrentOrgId => org.OrganizationId;

    public DbSet<Organization> Organizations => Set<Organization>();
    public DbSet<User> Users => Set<User>();
    public DbSet<Server> Servers => Set<Server>();
    public DbSet<EnrollmentKey> EnrollmentKeys => Set<EnrollmentKey>();
    public DbSet<Tenant> Tenants => Set<Tenant>();
    public DbSet<Asset> Assets => Set<Asset>();
    public DbSet<KellaEvent> Events => Set<KellaEvent>();
    public DbSet<Finding> Findings => Set<Finding>();
    public DbSet<Incident> Incidents => Set<Incident>();
    public DbSet<KellaAction> Actions => Set<KellaAction>();
    public DbSet<AgentCommand> AgentCommands => Set<AgentCommand>();
    public DbSet<AuditEntry> AuditLog => Set<AuditEntry>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        b.Entity<Organization>().ToTable("organizations");
        b.Entity<User>().ToTable("users").HasIndex(x => x.Email).IsUnique();
        b.Entity<Server>().ToTable("servers").HasIndex(x => x.KeyHash);
        b.Entity<EnrollmentKey>().ToTable("enrollment_keys").HasIndex(x => x.KeyHash).IsUnique();
        b.Entity<Tenant>().ToTable("tenants");
        b.Entity<Asset>().ToTable("assets").HasIndex(x => new { x.OrganizationId, x.Kind, x.Identifier }).IsUnique();
        b.Entity<KellaEvent>().ToTable("events").HasIndex(x => new { x.OrganizationId, x.Ts });
        b.Entity<Finding>().ToTable("findings");
        b.Entity<Incident>().ToTable("incidents").HasIndex(x => new { x.OrganizationId, x.Number }).IsUnique();
        b.Entity<KellaAction>().ToTable("actions");
        b.Entity<AgentCommand>().ToTable("agent_commands").HasIndex(x => new { x.ServerId, x.Status });
        b.Entity<AuditEntry>().ToTable("audit_log");

        // Dictionaries/lists are stored as JSON. TODO(Phase 0): switch to jsonb columns via Npgsql when migrations are added.
        b.Entity<Server>().PrimitiveCollection(x => x.Detected);
        b.Entity<Server>().PrimitiveCollection(x => x.Guards);
        b.Entity<KellaEvent>().Property(x => x.Attrs).HasJsonConversion();
        b.Entity<Finding>().Property(x => x.Evidence).HasJsonConversion();
        b.Entity<KellaAction>().Property(x => x.Params).HasJsonConversion();
        b.Entity<AgentCommand>().Property(x => x.Params).HasJsonConversion();

        foreach (var type in b.Model.GetEntityTypes().Where(t => typeof(IOrgScoped).IsAssignableFrom(t.ClrType)))
        {
            var method = typeof(KellaDbContext).GetMethod(nameof(ApplyOrgFilter),
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!;
            method.MakeGenericMethod(type.ClrType).Invoke(this, [b]);
        }
    }

    private void ApplyOrgFilter<T>(ModelBuilder b) where T : class, IOrgScoped
    {
        Expression<Func<T, bool>> filter = e => CurrentOrgId != null && e.OrganizationId == CurrentOrgId;
        b.Entity<T>().HasQueryFilter(filter);
    }
}
