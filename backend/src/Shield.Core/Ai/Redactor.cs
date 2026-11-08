using System.Text.RegularExpressions;

namespace Shield.Core.Ai;

/// <summary>
/// Removes secrets and personal data before any text is sent to an AI provider (SPEC §13).
/// Mailboxes listed in <c>keepMailboxes</c> (the affected ones) stay readable; all others are masked.
/// </summary>
public static partial class Redactor
{
    [GeneratedRegex(@"(?i)(password|passwd|pwd|secret|token|api[_-]?key)(\s*[:=]\s*|""\s*:\s*"")([^\s"",;]+)")]
    private static partial Regex SecretPairs();

    [GeneratedRegex(@"(?i)\b(bearer)\s+[a-z0-9\-._~+/]+=*")]
    private static partial Regex BearerTokens();

    [GeneratedRegex(@"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")]
    private static partial Regex Emails();

    // International numbers written with "+", or Bangladeshi mobile numbers (01XXXXXXXXX).
    // Deliberately does not match dates, times or IP addresses.
    [GeneratedRegex(@"(?<![\w.:-])\+\d[\d\s\-]{7,14}\d(?!\d)|(?<![\w.:-])01[3-9]\d{8}(?!\d)")]
    private static partial Regex Phones();

    public static string Redact(string text, IReadOnlyCollection<string>? keepMailboxes = null)
    {
        var keep = new HashSet<string>(keepMailboxes ?? [], StringComparer.OrdinalIgnoreCase);

        text = BearerTokens().Replace(text, m => $"{m.Groups[1].Value} [REDACTED]");
        text = SecretPairs().Replace(text, m => $"{m.Groups[1].Value}{m.Groups[2].Value}[REDACTED]");
        text = Emails().Replace(text, m =>
        {
            if (keep.Contains(m.Value)) return m.Value;
            var domain = m.Value[(m.Value.IndexOf('@') + 1)..];
            return $"[user]@{domain}";
        });
        text = Phones().Replace(text, "[PHONE]");
        return text;
    }
}
