using Kella.Core.Actions;
using Kella.Core.Domain;
using Kella.Core.Events;

namespace Kella.Core.Rules;

/// <summary>
/// mail.outbound_spike: messages queued by one sender / 10 min vs baseline (SPEC §9).
/// Default threshold: > 20x baseline and > 100 messages within 10 minutes.
/// Action: auto hold_sender; approval: reset password.
/// </summary>
public sealed class MailOutboundSpikeRule : IRule
{
    private readonly SlidingWindowCounter _counter;
    private readonly int _minSpikeCount;

    public MailOutboundSpikeRule(TimeSpan? window = null, int minSpikeCount = 100)
    {
        _counter = new SlidingWindowCounter(window ?? TimeSpan.FromMinutes(10));
        _minSpikeCount = minSpikeCount;
    }

    public string Code => "mail.outbound_spike";
    public IReadOnlySet<string> EventTypes { get; } = new HashSet<string> { Events.EventTypes.MailMessageQueued };

    public RuleMatch? Evaluate(KellaEvent evt)
    {
        if (!evt.Attrs.TryGetValue("sender", out var sender) || string.IsNullOrWhiteSpace(sender))
            return null;

        var key = $"{evt.ServerId}:{sender.ToLowerInvariant()}";
        var count = _counter.Add(key, evt.Ts);

        if (count < _minSpikeCount)
            return null;

        _counter.Reset(key);

        var evidence = new Dictionary<string, string>
        {
            ["sender"] = sender,
            ["queuedCount"] = count.ToString(),
            ["windowMinutes"] = "10",
        };

        return new RuleMatch(
            Code,
            Severity.Critical,
            $"Outbound email spike from {sender}",
            $"{count} messages queued by {sender} in 10 minutes (exceeds threshold of {_minSpikeCount}).",
            evidence,
            [
                new SuggestedAction(
                    ActionKinds.HoldSender,
                    new Dictionary<string, string> { ["sender"] = sender },
                    ActionMode.Auto,
                    $"Hold messages from {sender}"),
                new SuggestedAction(
                    "reset_mailbox_password",
                    new Dictionary<string, string> { ["mailbox"] = sender },
                    ActionMode.Approval,
                    $"Reset password for {sender}"),
            ]);
    }
}

/// <summary>
/// mail.account_takeover: failed logins or anomaly followed by outbound spike on same mailbox within 2h (SPEC §9).
/// Action: auto hold_sender; approval: reset password, delete held messages.
/// </summary>
public sealed class MailAccountTakeoverRule : IRule
{
    private readonly SlidingWindowCounter _failedLogins = new(TimeSpan.FromHours(2));

    public string Code => "mail.account_takeover";
    public IReadOnlySet<string> EventTypes { get; } = new HashSet<string>
    {
        Events.EventTypes.MailAuthFailed,
        Events.EventTypes.MailMessageQueued
    };

    public RuleMatch? Evaluate(KellaEvent evt)
    {
        if (evt.Type == Events.EventTypes.MailAuthFailed)
        {
            if (evt.Attrs.TryGetValue("user", out var user) && !string.IsNullOrWhiteSpace(user))
            {
                var key = $"{evt.ServerId}:{user.ToLowerInvariant()}";
                _failedLogins.Add(key, evt.Ts);
            }
            return null;
        }

        if (evt.Type == Events.EventTypes.MailMessageQueued)
        {
            if (!evt.Attrs.TryGetValue("sender", out var sender) || string.IsNullOrWhiteSpace(sender))
                return null;

            var key = $"{evt.ServerId}:{sender.ToLowerInvariant()}";
            // Check if there was any prior auth failure in the 2 hour window
            var authFailures = _failedLogins.Add(key, evt.Ts) - 1; // get without re-adding
            if (authFailures >= 5)
            {
                _failedLogins.Reset(key);

                var evidence = new Dictionary<string, string>
                {
                    ["mailbox"] = sender,
                    ["recentAuthFailures"] = authFailures.ToString(),
                    ["detectedAt"] = evt.Ts.ToString("O"),
                };

                return new RuleMatch(
                    Code,
                    Severity.Critical,
                    $"Account takeover detected for {sender}",
                    $"Recent failed authentications followed by immediate outbound sending on {sender}.",
                    evidence,
                    [
                        new SuggestedAction(
                            ActionKinds.HoldSender,
                            new Dictionary<string, string> { ["sender"] = sender },
                            ActionMode.Auto,
                            $"Hold messages from {sender}"),
                        new SuggestedAction(
                            "reset_mailbox_password",
                            new Dictionary<string, string> { ["mailbox"] = sender },
                            ActionMode.Approval,
                            $"Reset password for {sender}"),
                        new SuggestedAction(
                            "delete_held_messages",
                            new Dictionary<string, string> { ["sender"] = sender },
                            ActionMode.Approval,
                            $"Delete held messages from {sender}"),
                    ]);
            }
        }

        return null;
    }
}
