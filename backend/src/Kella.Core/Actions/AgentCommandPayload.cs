using System.Text.Json;

namespace Kella.Core.Actions;

/// <summary>Stored in <c>agent_commands.payload</c> (SPEC §6) and sent to the agent as a command.</summary>
public sealed record AgentCommandPayload(string Kind, Dictionary<string, string> Params, DateTimeOffset ExpiresAt);

public static class AgentCommandPayloadJson
{
    private static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web);

    public static string Serialize(AgentCommandPayload payload) => JsonSerializer.Serialize(payload, Options);

    public static AgentCommandPayload? TryParse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try { return JsonSerializer.Deserialize<AgentCommandPayload>(json, Options); }
        catch (JsonException) { return null; }
    }
}
