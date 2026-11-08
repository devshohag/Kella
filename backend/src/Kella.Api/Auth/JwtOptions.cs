using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace Kella.Api.Auth;

public sealed class JwtOptions
{
    public const string Section = "Kella:Jwt";

    public string Issuer { get; set; } = "kella";
    public string Audience { get; set; } = "kella-web";
    /// <summary>At least 32 bytes. Load from KELLA__JWT__KEY in production; never commit it.</summary>
    public string? Key { get; set; }
    public int AccessMinutes { get; set; } = 15;
    public int RefreshDays { get; set; } = 30;
    public bool SecureCookies { get; set; } = true;

    public SymmetricSecurityKey SigningKey =>
        new(Encoding.UTF8.GetBytes(Key ?? throw new InvalidOperationException("Kella:Jwt:Key is required.")));

    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(Key) || Encoding.UTF8.GetByteCount(Key) < 32)
            throw new InvalidOperationException("Kella:Jwt:Key must be at least 32 bytes (256 bits).");
        if (AccessMinutes <= 0 || RefreshDays <= 0)
            throw new InvalidOperationException("Kella:Jwt access and refresh lifetimes must be positive.");
    }
}
