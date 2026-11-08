namespace Kella.Core;

public interface IBaselineProvider
{
    /// <summary>
    /// Gets the rolling p95 baseline for the entity. Returns null if fewer than 24h of data exist.
    /// </summary>
    double? GetP95(Guid organizationId, string entityKind, Guid entityId, int hourOfWeek);
}

public sealed class InMemoryBaselineProvider : IBaselineProvider
{
    private readonly Dictionary<string, double> _p95Values = new();

    public void SetBaseline(Guid organizationId, string entityKind, Guid entityId, int hourOfWeek, double p95)
    {
        _p95Values[$"{organizationId}:{entityKind}:{entityId}:{hourOfWeek}"] = p95;
    }

    public double? GetP95(Guid organizationId, string entityKind, Guid entityId, int hourOfWeek)
    {
        var key = $"{organizationId}:{entityKind}:{entityId}:{hourOfWeek}";
        return _p95Values.TryGetValue(key, out var val) ? val : null;
    }
}
