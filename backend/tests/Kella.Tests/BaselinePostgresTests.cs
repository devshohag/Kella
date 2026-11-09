using System;
using System.Linq;
using System.Threading.Tasks;
using Kella.Core.Domain;
using Kella.Core.Events;
using Kella.Infrastructure.Data;
using Kella.Infrastructure.Pipeline;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using Testcontainers.PostgreSql;
using Xunit;

namespace Kella.Tests;

/// <summary>
/// Runs the production baseline aggregation SQL against a real Postgres instance so that
/// timezone-dependent EXTRACT() behaviour is exercised (SPEC §9).
/// </summary>
public class BaselinePostgresTests : IAsyncLifetime
{
    private readonly PostgreSqlContainer _postgres = new PostgreSqlBuilder("postgres:16-alpine")
        .Build();

    public Task InitializeAsync() => _postgres.StartAsync();

    public Task DisposeAsync() => _postgres.DisposeAsync().AsTask();

    [Fact]
    public async Task BucketAggregationSql_computes_hour_of_week_in_utc_with_non_utc_session_timezone()
    {
        // Force every connection used by the test to a non-UTC session timezone. Without
        // AT TIME ZONE 'UTC' the SQL would compute Monday 04:30 instead of Sunday 22:30 UTC.
        var connectionString = new NpgsqlConnectionStringBuilder(_postgres.GetConnectionString())
        {
            Options = "-c TimeZone=Asia/Dhaka",
        }.ConnectionString;

        var options = new DbContextOptionsBuilder<KellaDbContext>()
            .UseNpgsql(connectionString)
            .Options;

        using var db = new KellaDbContext(options, new NullOrgContext());
        await db.Database.EnsureCreatedAsync();

        var org = new Organization { Name = "Baseline Postgres Org" };
        var server = new Server { OrganizationId = org.Id, Name = "pg-baseline-srv" };
        var ts = new DateTimeOffset(2026, 11, 8, 22, 30, 0, TimeSpan.Zero); // Sunday 22:30 UTC

        db.Organizations.Add(org);
        db.Servers.Add(server);
        db.Events.Add(new KellaEvent
        {
            OrganizationId = org.Id,
            ServerId = server.Id,
            Ts = ts,
            Module = Modules.Mail,
            Type = EventTypes.MailMessageQueued,
            Attrs = new()
            {
                ["sender"] = "sender@example.com",
                ["authenticated"] = "true",
            },
        });
        await db.SaveChangesAsync();

        var rows = await db.Database
            .SqlQueryRaw<SenderBucketRow>(BaselineWriterService.BucketAggregationSql, ts.AddDays(-1))
            .ToListAsync();

        var row = Assert.Single(rows);
        Assert.Equal(166, row.HourOfWeek); // Sunday = 6, 6 * 24 + 22
        Assert.Equal(ts.ToUnixTimeSeconds() / 600, row.BucketId);
        Assert.Equal("sender@example.com", row.Sender);
    }

    private sealed class NullOrgContext : Kella.Core.IOrgContext
    {
        public Guid? OrganizationId => null;
    }
}
