using Kella.Core.Actions;
using Kella.Core.Domain;
using Kella.Core.Events;

namespace Kella.Core.Rules;

/// <summary>Shared defaults for Mail Guard actions (SPEC §8.5, §9).</summary>
public static class MailDefaults
{
    /// <summary>A held sender is released automatically after four hours unless an operator releases sooner.</summary>
    public const int HoldTtlSeconds = 4 * 60 * 60;
}

/// <summary>
/// mail.outbound_spike: messages queued by one sender / 10 min vs baseline (SPEC §9).
/// Default threshold: > 20x baseline and > 100 messages within 10 minutes.
/// Action: auto hold_sender; approval: reset password.
/// </summary>
public sealed class MailOutboundSpikeRule : IRule
{
    private readonly SlidingWindowCounter _counter;
    private readonly int _minSpikeCount;
    private readonly int _holdTtlSeconds;
    private readonly IBaselineProvider? _baselines;

    public MailOutboundSpikeRule(TimeSpan? window = null, int minSpikeCount = 100, IBaselineProvider? baselines = null,
        int holdTtlSeconds = MailDefaults.HoldTtlSeconds)
    {
        _counter = new SlidingWindowCounter(window ?? TimeSpan.FromMinutes(10));
        _minSpikeCount = minSpikeCount;
        _holdTtlSeconds = holdTtlSeconds;
        _baselines = baselines;
    }

    public string Code => "mail.outbound_spike";
    public IReadOnlySet<string> EventTypes { get; } = new HashSet<string> { Events.EventTypes.MailMessageQueued };

    public RuleMatch? Evaluate(KellaEvent evt)
    {
        if (!evt.Attrs.TryGetValue("authenticated", out var auth) || !string.Equals(auth, "true", StringComparison.OrdinalIgnoreCase))
            return null;

        string sender;
        if (evt.Attrs.TryGetValue("sasl_username", out var saslUser) && !string.IsNullOrWhiteSpace(saslUser))
        {
            sender = saslUser.Trim();
        }
        else if (evt.Attrs.TryGetValue("sender", out var envSender) && !string.IsNullOrWhiteSpace(envSender))
        {
            sender = envSender.Trim();
        }
        else
        {
            return null;
        }

        var senderLower = sender.ToLowerInvariant();
        var key = $"{evt.ServerId}:{senderLower}";
        var count = _counter.Add(key, evt.Ts);

        // Check against baselines if 24h data exist (SPEC §9)
        // hour of week in UTC: 0 = Monday 00:00 ... 167 = Sunday 23:00
        var utc = evt.Ts.UtcDateTime;
        int dayIndex = ((int)utc.DayOfWeek + 6) % 7; // Monday=0 ... Sunday=6
        int hourOfWeek = (dayIndex * 24) + utc.Hour;

        var p95 = _baselines?.GetP95(evt.OrganizationId, "mailbox", key, hourOfWeek);

        bool isSpike;
        if (p95.HasValue && p95.Value > 0)
        {
            // SPEC §9: > 20x and > 100 msgs vs its own p95
            isSpike = count > _minSpikeCount && count > (p95.Value * 20);
        }
        else
        {
            // Fixed threshold before 24h of data exist
            isSpike = count >= _minSpikeCount;
        }

        if (!isSpike)
            return null;

        _counter.Reset(key);

        var evidence = new Dictionary<string, string>
        {
            ["sender"] = sender,
            ["queuedCount"] = count.ToString(),
            ["windowMinutes"] = "10",
        };
        if (p95.HasValue) evidence["baselineP95"] = p95.Value.ToString("F1");

        return new RuleMatch(
            Code,
            Severity.Critical,
            $"Outbound email spike from {sender}",
            $"{count} messages queued by {sender} in 10 minutes (exceeds threshold of {_minSpikeCount}). Note: Password reset must be done manually by the admin.",
            evidence,
            [
                new SuggestedAction(
                    ActionKinds.HoldSender,
                    new Dictionary<string, string>
                    {
                        ["sender"] = sender,
                        ["ttlSec"] = _holdTtlSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture),
                    },
                    ActionMode.Auto,
                    $"Hold messages from {sender} (auto-release after {_holdTtlSeconds / 3600}h)")
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
    private readonly SlidingWindowCounter _outboundCounts = new(TimeSpan.FromMinutes(10));
    private readonly int _minOutboundSpike;
    private readonly int _holdTtlSeconds;

    public MailAccountTakeoverRule(int minOutboundSpike = 50,
        int holdTtlSeconds = MailDefaults.HoldTtlSeconds)
    {
        _minOutboundSpike = minOutboundSpike;
        _holdTtlSeconds = holdTtlSeconds;
    }

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
            if (!evt.Attrs.TryGetValue("authenticated", out var auth) || !string.Equals(auth, "true", StringComparison.OrdinalIgnoreCase))
                return null;

            string sender;
            if (evt.Attrs.TryGetValue("sasl_username", out var saslUser) && !string.IsNullOrWhiteSpace(saslUser))
            {
                sender = saslUser.Trim();
            }
            else if (evt.Attrs.TryGetValue("sender", out var envSender) && !string.IsNullOrWhiteSpace(envSender))
            {
                sender = envSender.Trim();
            }
            else
            {
                return null;
            }

            var key = $"{evt.ServerId}:{sender.ToLowerInvariant()}";

            // Track outbound messages without polluting the auth failure counter
            var outboundCount = _outboundCounts.Add(key, evt.Ts);
            if (outboundCount < _minOutboundSpike)
                return null;

            // Check if there was prior auth failure or anomaly in the 2 hour window
            var authFailures = _failedLogins.Count(key, evt.Ts);
            if (authFailures >= 5)
            {
                _failedLogins.Reset(key);
                _outboundCounts.Reset(key);

                var evidence = new Dictionary<string, string>
                {
                    ["mailbox"] = sender,
                    ["recentAuthFailures"] = authFailures.ToString(),
                    ["outboundMessages"] = outboundCount.ToString(),
                    ["detectedAt"] = evt.Ts.ToString("O"),
                };

                return new RuleMatch(
                    Code,
                    Severity.Critical,
                    $"Account takeover detected for {sender}",
                    $"{authFailures} recent failed authentications followed by outbound spike ({outboundCount} msgs) on {sender}. Note: Password reset and message purge must be done manually by the admin.",
                    evidence,
                    [
                        new SuggestedAction(
                            ActionKinds.HoldSender,
                            new Dictionary<string, string>
                            {
                                ["sender"] = sender,
                                ["ttlSec"] = _holdTtlSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture),
                            },
                            ActionMode.Auto,
                            $"Hold messages from {sender} (auto-release after {_holdTtlSeconds / 3600}h)")
                    ]);
            }
        }

        return null;
    }
}
