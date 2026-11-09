using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Kella.Core.Actions;
using Kella.Core.Domain;
using Kella.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;

namespace Kella.Infrastructure.Pipeline;

public static class ActionLifecycleHelper
{
    public static async Task MarkActionSucceededAsync(KellaDbContext db, KellaAction action, CancellationToken ct = default)
    {
        action.Status = ActionStatus.Succeeded;
        action.ExecutedAt = DateTimeOffset.UtcNow;

        if (action.Kind == ActionKinds.ReleaseSender && action.Params.TryGetValue("sender", out var sender))
        {
            var priorHolds = await db.Actions
                .IgnoreQueryFilters()
                .Where(a => a.ServerId == action.ServerId && a.Kind == ActionKinds.HoldSender &&
                            (a.Status == ActionStatus.Succeeded || a.Status == ActionStatus.Sent || a.Status == ActionStatus.Queued))
                .ToListAsync(ct);

            foreach (var h in priorHolds)
            {
                if (h.Params.TryGetValue("sender", out var s) && string.Equals(s, sender, StringComparison.OrdinalIgnoreCase))
                {
                    h.Status = ActionStatus.Reverted;
                }
            }
        }
    }
}
