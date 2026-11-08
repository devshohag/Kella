using System.Text.Json;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Kella.Infrastructure.Data;

internal static class JsonConversion
{
    public static PropertyBuilder<Dictionary<string, string>> HasJsonConversion(this PropertyBuilder<Dictionary<string, string>> p)
    {
        var comparer = new ValueComparer<Dictionary<string, string>>(
            (a, b) => JsonSerializer.Serialize(a, (JsonSerializerOptions?)null) == JsonSerializer.Serialize(b, (JsonSerializerOptions?)null),
            v => JsonSerializer.Serialize(v, (JsonSerializerOptions?)null).GetHashCode(),
            v => new Dictionary<string, string>(v));

        p.HasConversion(
            v => JsonSerializer.Serialize(v, (JsonSerializerOptions?)null),
            v => JsonSerializer.Deserialize<Dictionary<string, string>>(v, (JsonSerializerOptions?)null) ?? new());
        p.Metadata.SetValueComparer(comparer);
        return p;
    }
}
