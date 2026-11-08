using Shield.Core.Actions;
using Shield.Core.Domain;
using Shield.Core.Events;

namespace Shield.Core.Rules;

/// <summary>
/// Base for "N failures from one IP within a window → block the IP" rules (SPEC §9).
/// Fires once when the threshold is crossed, then resets that IP's counter.
/// </summary>
public abstract class PerIpFailureRule(int threshold, TimeSpan window, TimeSpan blockFor) : IRule
{
    private readonly SlidingWindowCounter _counter = new(window);

    public abstract string Code { get; }
    public abstract IReadOnlySet<string> EventTypes { get; }
    protected abstract string Describe(ShieldEvent evt, int count);

    public int Threshold => threshold;

    public RuleMatch? Evaluate(ShieldEvent evt)
    {
        if (string.IsNullOrEmpty(evt.SourceIp)) return null;

        var key = $"{evt.ServerId}:{evt.SourceIp}";
        var count = _counter.Add(key, evt.Ts);
        if (count < threshold) return null;

        _counter.Reset(key);
        var evidence = new Dictionary<string, string>
        {
            ["sourceIp"] = evt.SourceIp,
            ["failures"] = count.ToString(),
            ["windowMinutes"] = ((int)window.TotalMinutes).ToString(),
        };
        if (evt.Attrs.TryGetValue("user", out var user)) evidence["lastUser"] = user;

        return new RuleMatch(
            Code,
            Severity.Warning,
            Describe(evt, count),
            $"{count} failed logins from {evt.SourceIp} in {(int)window.TotalMinutes} minutes.",
            evidence,
            [
                new SuggestedAction(
                    ActionKinds.BlockIp,
                    new Dictionary<string, string> { ["ip"] = evt.SourceIp, ["ttlSec"] = ((int)blockFor.TotalSeconds).ToString() },
                    ActionMode.Auto,
                    $"Block {evt.SourceIp} for {(int)blockFor.TotalHours} hours"),
            ]);
    }
}

public sealed class SshBruteForceRule() : PerIpFailureRule(10, TimeSpan.FromMinutes(10), TimeSpan.FromHours(24))
{
    public override string Code => "ssh.bruteforce";
    public override IReadOnlySet<string> EventTypes { get; } = new HashSet<string> { Events.EventTypes.SshAuthFailed };
    protected override string Describe(ShieldEvent evt, int count) => $"SSH password guessing from {evt.SourceIp}";
}

public sealed class MailBruteForceIpRule() : PerIpFailureRule(10, TimeSpan.FromMinutes(10), TimeSpan.FromHours(24))
{
    public override string Code => "mail.bruteforce_ip";
    public override IReadOnlySet<string> EventTypes { get; } = new HashSet<string> { Events.EventTypes.MailAuthFailed };
    protected override string Describe(ShieldEvent evt, int count) => $"Mail password guessing from {evt.SourceIp}";
}
