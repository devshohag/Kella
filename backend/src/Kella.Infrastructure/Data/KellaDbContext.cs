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
    public DbSet<Rule> Rules => Set<Rule>();
    public DbSet<AlertRoute> AlertRoutes => Set<AlertRoute>();
    public DbSet<AlertDelivery> AlertDeliveries => Set<AlertDelivery>();
    public DbSet<Baseline> Baselines => Set<Baseline>();
    public DbSet<AuditEntry> AuditLog => Set<AuditEntry>();
    public DbSet<TelegramUpdate> TelegramUpdates => Set<TelegramUpdate>();
    public DbSet<IpReputation> IpReputations => Set<IpReputation>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        b.Entity<Organization>().ToTable("organizations");
        b.Entity<Organization>().Property(x => x.Settings).HasJsonConversion().HasColumnType("jsonb");

        b.Entity<User>().ToTable("users").HasIndex(x => x.Email).IsUnique();

        b.Entity<Server>().ToTable("servers").HasIndex(x => x.KeyHash);
        b.Entity<Server>().PrimitiveCollection(x => x.Detected).HasColumnType("jsonb");
        b.Entity<Server>().PrimitiveCollection(x => x.Guards).HasColumnType("text[]");

        b.Entity<EnrollmentKey>().ToTable("enrollment_keys").HasIndex(x => x.KeyHash).IsUnique();

        b.Entity<Tenant>().ToTable("tenants");

        b.Entity<Asset>().ToTable("assets").HasIndex(x => new { x.OrganizationId, x.Kind, x.Identifier }).IsUnique();
        b.Entity<Asset>().Property(x => x.Meta).HasJsonConversion().HasColumnType("jsonb");

        // events is range-partitioned by ts in the migration; a partitioned table's primary key must contain it.
        b.Entity<KellaEvent>().ToTable("events").HasKey(x => new { x.Id, x.Ts });
        b.Entity<KellaEvent>().HasIndex(x => new { x.OrganizationId, x.Ts });
        b.Entity<KellaEvent>().Property(x => x.Attrs).HasJsonConversion().HasColumnType("jsonb");

        b.Entity<Finding>().ToTable("findings");
        b.Entity<Finding>().Property(x => x.Evidence).HasJsonConversion().HasColumnType("jsonb");

        b.Entity<Incident>().ToTable("incidents").HasIndex(x => new { x.OrganizationId, x.Number }).IsUnique();
        b.Entity<Incident>().Property(x => x.AiAnalysisJson).HasColumnType("jsonb");

        b.Entity<KellaAction>().ToTable("actions");
        b.Entity<KellaAction>().Property(x => x.Params).HasJsonConversion().HasColumnType("jsonb");
        b.Entity<KellaAction>().Property(x => x.ResultJson).HasColumnType("jsonb");

        b.Entity<AgentCommand>().ToTable("agent_commands").HasIndex(x => new { x.ServerId, x.Status });
        b.Entity<AgentCommand>().Property(x => x.Payload).HasColumnType("jsonb");

        b.Entity<Rule>().ToTable("rules").HasIndex(x => new { x.OrganizationId, x.Code }).IsUnique();
        b.Entity<Rule>().Property(x => x.Params).HasJsonConversion().HasColumnType("jsonb");
        // Built-in rules have no organization and are visible to everyone.
        b.Entity<Rule>().HasQueryFilter(r => r.OrganizationId == null || r.OrganizationId == CurrentOrgId);

        b.Entity<AlertRoute>().ToTable("alert_routes").HasIndex(x => new { x.OrganizationId, x.Severity }).IsUnique();
        b.Entity<AlertRoute>().PrimitiveCollection(x => x.Channels).HasColumnType("text[]");

        b.Entity<AlertDelivery>().ToTable("alert_deliveries").HasIndex(x => new { x.OrganizationId, x.IncidentId });
        b.Entity<AlertDelivery>().ToTable("alert_deliveries").HasIndex(x => new { x.OrganizationId, x.ChatId, x.MessageId });
        b.Entity<AlertDelivery>().PrimitiveCollection(x => x.ActionIds).HasColumnType("uuid[]");

        b.Entity<Baseline>().ToTable("baselines").HasIndex(x => new { x.OrganizationId, x.EntityKind, x.EntityId, x.HourOfWeek }).IsUnique();

        b.Entity<AuditEntry>().ToTable("audit_log").HasIndex(x => new { x.OrganizationId, x.Ts });
        b.Entity<AuditEntry>().Property(x => x.DataJson).HasColumnType("jsonb");

        b.Entity<TelegramUpdate>().ToTable("telegram_updates").HasKey(x => x.UpdateId);
        b.Entity<TelegramUpdate>().Property(x => x.UpdateId).ValueGeneratedNever();

        b.Entity<IpReputation>().ToTable("ip_reputation").HasIndex(x => new { x.OrganizationId, x.Ip }).IsUnique();

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
