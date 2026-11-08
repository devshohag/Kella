using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Kella.Core.Domain;
using Microsoft.IdentityModel.Tokens;

namespace Kella.Api.Auth;

/// <summary>Issues and validates the access, refresh and two-factor setup tokens carried in httpOnly cookies (SPEC §5).</summary>
public sealed class AuthTokens(JwtOptions options)
{
    public const string AccessCookie = "kella_access";
    public const string RefreshCookie = "kella_refresh";
    public const string AccessType = "access";
    public const string RefreshType = "refresh";
    public const string TotpSetupType = "totp_setup";

    public string CreateAccessToken(User user) =>
        Write(user, AccessType, TimeSpan.FromMinutes(options.AccessMinutes));

    public string CreateRefreshToken(User user) =>
        Write(user, RefreshType, TimeSpan.FromDays(options.RefreshDays));

    /// <summary>
    /// The pending secret lives in the signed setup token until the user proves possession of it, so an
    /// abandoned setup never leaves the account demanding a code the user never saved.
    /// </summary>
    public string CreateTotpSetupToken(User user, string secret) =>
        Write(user, TotpSetupType, TimeSpan.FromMinutes(10), new Claim("totp", secret));

    public void SetSessionCookies(HttpResponse response, User user)
    {
        var now = DateTimeOffset.UtcNow;
        response.Cookies.Append(AccessCookie, CreateAccessToken(user), new CookieOptions
        {
            HttpOnly = true,
            Secure = options.SecureCookies,
            SameSite = SameSiteMode.Lax,
            Path = "/",
            Expires = now.AddMinutes(options.AccessMinutes),
            IsEssential = true,
        });
        response.Cookies.Append(RefreshCookie, CreateRefreshToken(user), new CookieOptions
        {
            HttpOnly = true,
            Secure = options.SecureCookies,
            SameSite = SameSiteMode.Lax,
            Path = "/api/auth",
            Expires = now.AddDays(options.RefreshDays),
            IsEssential = true,
        });
    }

    public void ClearSessionCookies(HttpResponse response)
    {
        response.Cookies.Delete(AccessCookie, new CookieOptions { Path = "/", Secure = options.SecureCookies, SameSite = SameSiteMode.Lax });
        response.Cookies.Delete(RefreshCookie, new CookieOptions { Path = "/api/auth", Secure = options.SecureCookies, SameSite = SameSiteMode.Lax });
    }

    /// <summary>Validates a token of the given type and returns its claims, or null when it is invalid or expired.</summary>
    public ClaimsPrincipal? Validate(string? token, string expectedType)
    {
        if (string.IsNullOrWhiteSpace(token)) return null;
        try
        {
            var handler = new JwtSecurityTokenHandler { MapInboundClaims = false };
            var principal = handler.ValidateToken(token, new TokenValidationParameters
            {
                ValidIssuer = options.Issuer,
                ValidAudience = options.Audience,
                IssuerSigningKey = options.SigningKey,
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateIssuerSigningKey = true,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.FromSeconds(30),
                NameClaimType = "name",
            }, out _);
            return principal.FindFirst("typ")?.Value == expectedType ? principal : null;
        }
        catch (SecurityTokenException)
        {
            return null;
        }
        catch (ArgumentException)
        {
            return null;
        }
    }

    private string Write(User user, string type, TimeSpan lifetime, params Claim[] extra)
    {
        var now = DateTime.UtcNow;
        var claims = new List<Claim>
        {
            new("sub", user.Id.ToString()),
            new("org", user.OrganizationId.ToString()),
            new("role", user.Role.ToString()),
            new("email", user.Email),
            new("name", user.Name),
            new("typ", type),
        };
        claims.AddRange(extra);
        var token = new JwtSecurityToken(
            issuer: options.Issuer,
            audience: options.Audience,
            claims: claims,
            notBefore: now,
            expires: now.Add(lifetime),
            signingCredentials: new SigningCredentials(options.SigningKey, SecurityAlgorithms.HmacSha256));
        return new JwtSecurityTokenHandler { MapInboundClaims = false }.WriteToken(token);
    }
}
