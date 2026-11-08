using System.Security.Cryptography;
using System.Text;

namespace Shield.Infrastructure.Security;

public static class Tokens
{
    /// <summary>Random URL-safe token with a readable prefix, e.g. "sk_live_…".</summary>
    public static string Create(string prefix)
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        return prefix + Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    public static string Hash(string token) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(token)));
}
