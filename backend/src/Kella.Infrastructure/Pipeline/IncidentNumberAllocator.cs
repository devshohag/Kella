using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Kella.Core.Domain;
using Kella.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;

namespace Kella.Infrastructure.Pipeline;

public static class IncidentNumberAllocator
{
    public static async Task<int> AllocateNextNumberAsync(KellaDbContext db, Guid organizationId, CancellationToken ct = default)
    {
        var max = await db.Incidents.IgnoreQueryFilters()
            .Where(i => i.OrganizationId == organizationId)
            .MaxAsync(i => (int?)i.Number, ct);
        return (max ?? 2000) + 1;
    }

    public static async Task SaveIncidentWithRetryAsync(KellaDbContext db, Incident incident, CancellationToken ct = default)
    {
        if (db.Entry(incident).State == EntityState.Detached)
            db.Incidents.Add(incident);

        for (int attempt = 0; attempt < 5; attempt++)
        {
            incident.Number = await AllocateNextNumberAsync(db, incident.OrganizationId, ct);
            try
            {
                await db.SaveChangesAsync(ct);
                return;
            }
            catch (DbUpdateException) when (attempt < 4)
            {
                // Unique constraint violation on (organization_id, number) under concurrency; retry with new number
                db.Entry(incident).State = EntityState.Added;
            }
        }
    }
}
