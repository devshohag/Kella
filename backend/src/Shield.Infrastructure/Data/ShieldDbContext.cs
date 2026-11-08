using System.Linq.Expressions;
using Microsoft.EntityFrameworkCore;
using Shield.Core;
using Shield.Core.Domain;

namespace Shield.Infrastructure.Data;

/// <summary>
/// Every <see cref="IOrgScoped"/> entity is filtered to the current organization.
/// Rows are invisible when no organization is set (e.g. anonymous requests).
/// </summary>
public sealed class ShieldDbContext(DbContextOptions<ShieldDbContext> options, IOrgContext org) : DbContext(options)
{
    private Guid? CurrentOrgId => org.OrganizationId;

    public DbSet<Organization> Organizations => Set<Organization>();
    public DbSet<User> Users => Set<User>();
    public DbSet<Server> Servers => Set<Server>();
    public DbSet<EnrollmentKey> EnrollmentKeys => Set<EnrollmentKey>();
    public DbSet<Tenant> Tenants => Set<Tenant>();
    public DbSet<Asset> Assets => Set<Asset>();
    public DbSet<ShieldEvent> Events => Set<ShieldEvent>();
    public DbSet<Finding> Findings => Set<Finding>();
    public DbSet<Incident> Incidents => Set<Incident>();
    public DbSet<ShieldAction> Actions => Set<ShieldAction>();
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
        b.Entity<ShieldEvent>().ToTable("events").HasIndex(x => new { x.OrganizationId, x.Ts });
        b.Entity<Finding>().ToTable("findings");
        b.Entity<Incident>().ToTable("incidents").HasIndex(x => new { x.OrganizationId, x.Number }).IsUnique();
        b.Entity<ShieldAction>().ToTable("actions");
        b.Entity<AgentCommand>().ToTable("agent_commands").HasIndex(x => new { x.ServerId, x.Status });
        b.Entity<AuditEntry>().ToTable("audit_log");

        // Dictionaries/lists are stored as JSON. TODO(Phase 0): switch to jsonb columns via Npgsql when migrations are added.
        b.Entity<Server>().PrimitiveCollection(x => x.Detected);
        b.Entity<Server>().PrimitiveCollection(x => x.Guards);
        b.Entity<ShieldEvent>().Property(x => x.Attrs).HasJsonConversion();
        b.Entity<Finding>().Property(x => x.Evidence).HasJsonConversion();
        b.Entity<ShieldAction>().Property(x => x.Params).HasJsonConversion();
        b.Entity<AgentCommand>().Property(x => x.Params).HasJsonConversion();

        foreach (var type in b.Model.GetEntityTypes().Where(t => typeof(IOrgScoped).IsAssignableFrom(t.ClrType)))
        {
            var method = typeof(ShieldDbContext).GetMethod(nameof(ApplyOrgFilter),
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
