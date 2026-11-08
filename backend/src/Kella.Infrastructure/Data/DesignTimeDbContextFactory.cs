using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Kella.Core;

namespace Kella.Infrastructure.Data;

/// <summary>Lets <c>dotnet ef</c> build the model without starting the API.</summary>
public sealed class DesignTimeDbContextFactory : IDesignTimeDbContextFactory<KellaDbContext>
{
    public KellaDbContext CreateDbContext(string[] args)
    {
        var connection = Environment.GetEnvironmentVariable("KELLA_CONNECTION")
            ?? "Host=localhost;Database=kella;Username=kella;Password=kella-dev-password";
        var options = new DbContextOptionsBuilder<KellaDbContext>().UseNpgsql(connection).Options;
        return new KellaDbContext(options, new DesignTimeOrgContext());
    }

    private sealed class DesignTimeOrgContext : IOrgContext
    {
        public Guid? OrganizationId => null;
    }
}
