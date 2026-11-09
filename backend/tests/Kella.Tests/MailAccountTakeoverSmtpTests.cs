using System;
using System.Collections.Generic;
using Kella.Core;
using Kella.Core.Domain;
using Kella.Core.Events;
using Kella.Core.Rules;
using Xunit;

namespace Kella.Tests;

public class MailAccountTakeoverSmtpTests
{
    [Fact]
    public void Smtp_auth_failed_without_user_does_not_trigger_account_takeover()
    {
        var rule = new MailAccountTakeoverRule(minOutboundSpike: 5);
        var orgId = Guid.NewGuid();
        var serverId = Guid.NewGuid();
        var now = DateTimeOffset.UtcNow;

        // 1. Postfix smtpd SASL failure without username
        var authFailedEvt = new KellaEvent
        {
            OrganizationId = orgId,
            ServerId = serverId,
            Ts = now,
            Module = Modules.Mail,
            Type = EventTypes.MailAuthFailed,
            SourceIp = "198.51.100.55",
            Attrs = new() { ["service"] = "postfix-smtpd" } // No "user" attribute
        };

        var match1 = rule.Evaluate(authFailedEvt);
        Assert.Null(match1);

        // 2. Outbound spike for user@domain.com
        RuleMatch? takeoverMatch = null;
        for (int i = 0; i < 6; i++)
        {
            var queueEvt = new KellaEvent
            {
                OrganizationId = orgId,
                ServerId = serverId,
                Ts = now.AddMinutes(5).AddSeconds(i),
                Module = Modules.Mail,
                Type = EventTypes.MailMessageQueued,
                Attrs = new()
                {
                    ["authenticated"] = "true",
                    ["sasl_username"] = "user@domain.com",
                    ["sender"] = "user@domain.com"
                }
            };
            var m = rule.Evaluate(queueEvt);
            if (m != null) takeoverMatch = m;
        }

        // Must NOT match account takeover because the failed logins had no username
        Assert.Null(takeoverMatch);
    }

    [Fact]
    public void Auth_failed_with_user_triggers_account_takeover_on_spike()
    {
        var rule = new MailAccountTakeoverRule(minOutboundSpike: 5);
        var orgId = Guid.NewGuid();
        var serverId = Guid.NewGuid();
        var now = DateTimeOffset.UtcNow;

        // 1. Auth failures WITH user (at least 5 required)
        for (int i = 0; i < 5; i++)
        {
            var authFailedEvt = new KellaEvent
            {
                OrganizationId = orgId,
                ServerId = serverId,
                Ts = now.AddSeconds(i),
                Module = Modules.Mail,
                Type = EventTypes.MailAuthFailed,
                SourceIp = "198.51.100.55",
                Attrs = new() { ["service"] = "dovecot", ["user"] = "user@domain.com" }
            };
            rule.Evaluate(authFailedEvt);
        }

        // 2. Outbound spike for user@domain.com
        RuleMatch? takeoverMatch = null;
        for (int i = 0; i < 6; i++)
        {
            var queueEvt = new KellaEvent
            {
                OrganizationId = orgId,
                ServerId = serverId,
                Ts = now.AddMinutes(5).AddSeconds(i),
                Module = Modules.Mail,
                Type = EventTypes.MailMessageQueued,
                Attrs = new()
                {
                    ["authenticated"] = "true",
                    ["sasl_username"] = "user@domain.com",
                    ["sender"] = "user@domain.com"
                }
            };
            var m = rule.Evaluate(queueEvt);
            if (m != null) takeoverMatch = m;
        }

        Assert.NotNull(takeoverMatch);
        Assert.Equal("mail.account_takeover", takeoverMatch.RuleCode);
    }
}
