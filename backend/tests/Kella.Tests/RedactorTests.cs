using Kella.Core.Ai;

namespace Kella.Tests;

public class RedactorTests
{
    [Theory]
    [InlineData("password=hunter2 user=x", "password=[REDACTED] user=x")]
    [InlineData("api_key: abc123", "api_key: [REDACTED]")]
    [InlineData("Authorization: Bearer eyJhbGciOi.payload.sig", "Authorization: Bearer [REDACTED]")]
    public void Removes_secrets(string input, string expected) =>
        Assert.Equal(expected, Redactor.Redact(input));

    [Fact]
    public void Keeps_affected_mailbox_and_masks_others()
    {
        var text = "billing@rahmantraders.com sent mail to ceo@victim.com";
        var result = Redactor.Redact(text, ["billing@rahmantraders.com"]);
        Assert.Equal("billing@rahmantraders.com sent mail to [user]@victim.com", result);
    }

    [Theory]
    [InlineData("call +8801712345678 now", "call [PHONE] now")]
    [InlineData("call 01712345678 now", "call [PHONE] now")]
    public void Masks_phone_numbers(string input, string expected) =>
        Assert.Equal(expected, Redactor.Redact(input));

    [Theory]
    [InlineData("at 2026-11-08 02:14 from 91.214.44.180")]
    [InlineData("AS 212238 sent 1840 messages")]
    public void Leaves_dates_ips_and_counts_alone(string input) =>
        Assert.Equal(input, Redactor.Redact(input));
}
