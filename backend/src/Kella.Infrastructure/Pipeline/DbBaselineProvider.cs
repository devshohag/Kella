using Kella.Core;
using Kella.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Kella.Infrastructure.Pipeline;

public sealed class DbBaselineProvider(IServiceScopeFactory scopes) : IBaselineProvider
{
    public double? GetP95(Guid organizationId, string entityKind, Guid entityId, int hourOfWeek)
    {
        using var scope = scopes.CreateScope();
        scope.ServiceProvider.GetRequiredService<OrgContext>().Set(organizationId);
        var db = scope.ServiceProvider.GetRequiredService<KellaDbContext>();

        var baseline = db.Baselines
            .AsNoTracking()
            .FirstOrDefault(b => b.EntityKind == entityKind && b.EntityId == entityId && b.HourOfWeek == hourOfWeek);

        return baseline?.P95;
    }
}
