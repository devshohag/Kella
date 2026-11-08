using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Kella.Core.Auth;

/// <summary>
/// Time-based one-time passwords (RFC 6238) with SHA-1, six digits and a 30-second step,
/// compatible with Google Authenticator, 1Password and similar apps. Secrets use base32 (RFC 4648).
/// </summary>
public static class Totp
{
    public const int Digits = 6;
    public const int StepSeconds = 30;
    private const string Base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    public static string GenerateSecret() => Base32Encode(RandomNumberGenerator.GetBytes(20));

    public static string Code(string secret, DateTimeOffset at)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(secret);
        var counter = at.ToUnixTimeSeconds() / StepSeconds;
        Span<byte> message = stackalloc byte[8];
        BinaryPrimitives.WriteInt64BigEndian(message, counter);
        var hash = HMACSHA1.HashData(Base32Decode(secret), message);
        var offset = hash[^1] & 0x0f;
        var binary = ((hash[offset] & 0x7f) << 24)
                   | (hash[offset + 1] << 16)
                   | (hash[offset + 2] << 8)
                   | hash[offset + 3];
        return (binary % 1_000_000).ToString("D6");
    }

    /// <summary>Accepts the current code and one step either side to tolerate clock skew.</summary>
    public static bool Verify(string secret, string? code, DateTimeOffset at, int allowedDriftSteps = 1)
    {
        if (string.IsNullOrWhiteSpace(secret) || string.IsNullOrWhiteSpace(code)) return false;
        code = code.Trim();
        if (code.Length != Digits || !code.All(char.IsAsciiDigit)) return false;

        for (var step = -allowedDriftSteps; step <= allowedDriftSteps; step++)
        {
            var expected = Encoding.ASCII.GetBytes(Code(secret, at.AddSeconds(step * StepSeconds)));
            if (CryptographicOperations.FixedTimeEquals(expected, Encoding.ASCII.GetBytes(code))) return true;
        }
        return false;
    }

    public static string OtpauthUri(string issuer, string account, string secret) =>
        $"otpauth://totp/{Uri.EscapeDataString(issuer)}:{Uri.EscapeDataString(account)}" +
        $"?secret={secret}&issuer={Uri.EscapeDataString(issuer)}&algorithm=SHA1&digits={Digits}&period={StepSeconds}";

    private static string Base32Encode(ReadOnlySpan<byte> data)
    {
        var output = new StringBuilder((data.Length * 8 + 4) / 5);
        var buffer = 0;
        var bitsLeft = 0;
        foreach (var b in data)
        {
            buffer = (buffer << 8) | b;
            bitsLeft += 8;
            while (bitsLeft >= 5)
            {
                output.Append(Base32Alphabet[(buffer >> (bitsLeft - 5)) & 0x1f]);
                bitsLeft -= 5;
            }
        }
        if (bitsLeft > 0) output.Append(Base32Alphabet[(buffer << (5 - bitsLeft)) & 0x1f]);
        return output.ToString();
    }

    private static byte[] Base32Decode(string secret)
    {
        var data = secret.Trim().TrimEnd('=').ToUpperInvariant();
        var bytes = new List<byte>(data.Length * 5 / 8);
        var buffer = 0;
        var bitsLeft = 0;
        foreach (var c in data)
        {
            var value = c switch
            {
                >= 'A' and <= 'Z' => c - 'A',
                >= '2' and <= '7' => c - '2' + 26,
                _ => throw new FormatException("TOTP secret is not valid base32.")
            };
            buffer = (buffer << 5) | value;
            bitsLeft += 5;
            if (bitsLeft >= 8)
            {
                bytes.Add((byte)((buffer >> (bitsLeft - 8)) & 0xff));
                bitsLeft -= 8;
            }
        }
        return [.. bytes];
    }
}
