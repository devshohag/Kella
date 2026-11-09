using System.Collections.Concurrent;
using Kella.Core;
using Kella.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Kella.Infrastructure.Pipeline;

public sealed class DbBaselineProvider(IServiceScopeFactory scopes) : IBaselineProvider
{
    private readonly ConcurrentDictionary<string, double> _cache = new(StringComparer.Ordinal);

    public void UpdateCache(Guid organizationId, string entityKind, string entityId, int hourOfWeek, double p95)
    {
        _cache[CacheKey(organizationId, entityKind, entityId, hourOfWeek)] = p95;
    }

    public double? GetP95(Guid organizationId, string entityKind, string entityId, int hourOfWeek)
    {
        var key = CacheKey(organizationId, entityKind, entityId, hourOfWeek);
        return _cache.TryGetValue(key, out var val) ? val : null;
    }

    public void PopulateFromDatabase(Guid organizationId)
    {
        using var scope = scopes.CreateScope();
        scope.ServiceProvider.GetRequiredService<OrgContext>().Set(organizationId);
        var db = scope.ServiceProvider.GetRequiredService<KellaDbContext>();
        var baselines = db.Baselines.AsNoTracking().ToList();
        foreach (var b in baselines)
        {
            _cache[CacheKey(b.OrganizationId, b.EntityKind, b.EntityId, b.HourOfWeek)] = b.P95;
        }
    }

    private static string CacheKey(Guid organizationId, string entityKind, string entityId, int hourOfWeek) =>
        $"{organizationId}:{entityKind}:{entityId.ToLowerInvariant()}:{hourOfWeek}";
}
