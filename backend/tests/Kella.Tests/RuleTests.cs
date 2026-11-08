using Kella.Core.Actions;
using Kella.Core.Domain;
using Kella.Core.Events;
using Kella.Core.Rules;

namespace Kella.Tests;

public class RuleTests
{
    private static readonly Guid Server = Guid.NewGuid();

    private static KellaEvent Failed(string ip, DateTimeOffset at) => new()
    {
        OrganizationId = Guid.NewGuid(), ServerId = Server, Ts = at,
        Module = Modules.Server, Type = EventTypes.SshAuthFailed, SourceIp = ip,
        Attrs = new() { ["user"] = "root" },
    };

    [Fact]
    public void Ssh_bruteforce_fires_on_tenth_failure_within_window()
    {
        var rule = new SshBruteForceRule();
        var t0 = DateTimeOffset.Parse("2026-11-08T02:00:00Z");

        for (var i = 0; i < 9; i++)
            Assert.Null(rule.Evaluate(Failed("45.148.10.92", t0.AddSeconds(i * 30))));

        var match = rule.Evaluate(Failed("45.148.10.92", t0.AddMinutes(5)));

        Assert.NotNull(match);
        Assert.Equal("ssh.bruteforce", match.RuleCode);
        var action = Assert.Single(match.Actions);
        Assert.Equal(ActionKinds.BlockIp, action.Kind);
        Assert.Equal("45.148.10.92", action.Params["ip"]);
        Assert.Equal(ActionMode.Auto, action.Mode);
    }

    [Fact]
    public void Ssh_bruteforce_ignores_failures_spread_beyond_window()
    {
        var rule = new SshBruteForceRule();
        var t0 = DateTimeOffset.Parse("2026-11-08T02:00:00Z");

        for (var i = 0; i < 20; i++)
            Assert.Null(rule.Evaluate(Failed("45.148.10.92", t0.AddMinutes(i * 2))));
    }

    [Fact]
    public void Ssh_bruteforce_counts_each_ip_separately()
    {
        var rule = new SshBruteForceRule();
        var t0 = DateTimeOffset.Parse("2026-11-08T02:00:00Z");

        for (var i = 0; i < 9; i++)
        {
            Assert.Null(rule.Evaluate(Failed("10.0.0.1", t0.AddSeconds(i))));
            Assert.Null(rule.Evaluate(Failed("10.0.0.2", t0.AddSeconds(i))));
        }
    }

    [Fact]
    public void Events_without_source_ip_are_ignored()
    {
        var rule = new MailBruteForceIpRule();
        var evt = Failed("x", DateTimeOffset.UtcNow);
        evt.SourceIp = null;
        Assert.Null(rule.Evaluate(evt));
    }

    [Fact]
    public void Mail_outbound_spike_fires_when_threshold_exceeded()
    {
        var rule = new MailOutboundSpikeRule(minSpikeCount: 5);
        var t0 = DateTimeOffset.Parse("2026-11-08T02:00:00Z");

        for (var i = 0; i < 4; i++)
        {
            var evt = new KellaEvent
            {
                OrganizationId = Guid.NewGuid(),
                ServerId = Server,
                Ts = t0.AddSeconds(i * 10),
                Module = Modules.Mail,
                Type = EventTypes.MailMessageQueued,
                Attrs = new() { ["sender"] = "billing@rahmantraders.com" }
            };
            Assert.Null(rule.Evaluate(evt));
        }

        var spikeEvt = new KellaEvent
        {
            OrganizationId = Guid.NewGuid(),
            ServerId = Server,
            Ts = t0.AddSeconds(50),
            Module = Modules.Mail,
            Type = EventTypes.MailMessageQueued,
            Attrs = new() { ["sender"] = "billing@rahmantraders.com" }
        };

        var match = rule.Evaluate(spikeEvt);
        Assert.NotNull(match);
        Assert.Equal("mail.outbound_spike", match.RuleCode);
        Assert.Equal(Severity.Critical, match.Severity);
        Assert.Contains(match.Actions, a => a.Kind == ActionKinds.HoldSender && a.Mode == ActionMode.Auto);
    }
}
