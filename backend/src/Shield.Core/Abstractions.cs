using Shield.Core.Domain;

namespace Shield.Core;

/// <summary>The organization the current request or job runs for. Drives the EF Core query filter.</summary>
public interface IOrgContext
{
    Guid? OrganizationId { get; }
}

/// <summary>Event bus between ingest and workers. Phase 0: in-process channel. Later: NATS JetStream.</summary>
public interface IEventBus
{
    ValueTask PublishAsync(ShieldEvent evt, CancellationToken ct);
    IAsyncEnumerable<ShieldEvent> SubscribeAsync(CancellationToken ct);
}

/// <summary>A suggested action produced by a rule; turned into <see cref="ShieldAction"/> by the playbook runner.</summary>
public sealed record SuggestedAction(string Kind, IReadOnlyDictionary<string, string> Params, ActionMode Mode, string Label);

/// <summary>Result of a rule match before it is persisted.</summary>
public sealed record RuleMatch(
    string RuleCode,
    Severity Severity,
    string Title,
    string Summary,
    IReadOnlyDictionary<string, string> Evidence,
    IReadOnlyList<SuggestedAction> Actions);

/// <summary>Deterministic detection rule. Must never call an LLM or do I/O.</summary>
public interface IRule
{
    string Code { get; }
    /// <summary>Event types this rule wants to see.</summary>
    IReadOnlySet<string> EventTypes { get; }
    RuleMatch? Evaluate(ShieldEvent evt);
}

public enum AlertChannelKind { Email, Telegram, WhatsApp, Voice }

public sealed record AlertMessage(Guid IncidentId, Severity Severity, string Title, string Body, IReadOnlyList<string> ReplyOptions);

public interface IAlertChannel
{
    AlertChannelKind Kind { get; }
    Task SendAsync(User recipient, AlertMessage message, CancellationToken ct);
}

public sealed record AiAnalysis(string WhatHappened, string Impact, IReadOnlyList<string> RecommendedActions, string CustomerNote, string Confidence);

public interface IAiProvider
{
    string Name { get; }
    /// <summary>Context must already be redacted (see <see cref="Ai.Redactor"/>).</summary>
    Task<AiAnalysis> AnalyzeIncidentAsync(string redactedContextJson, string language, CancellationToken ct);
}
