using System.Security.Claims;
using Kella.Api.Auth;
using Kella.Core.Auth;
using Kella.Core.Domain;
using Kella.Infrastructure;
using Kella.Infrastructure.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace Kella.Api.Endpoints;

public sealed record LoginRequest(string Email, string Password, string? TotpCode);
public sealed record LoginResponse(bool TotpSetupRequired, string? SetupToken, AuthUserDto? User);
public sealed record AuthUserDto(Guid Id, string Email, string Name, string Role, Guid OrganizationId, string OrganizationName);
public sealed record TotpSetupRequest(string SetupToken);
public sealed record TotpSetupResponse(string Secret, string OtpauthUri);
public sealed record TotpEnableRequest(string SetupToken, string Code);

/// <summary>Email + password, optional TOTP, and JWT access/refresh cookies (SPEC §5, §14).</summary>
public static class AuthEndpoints
{
    private const int MaxFailedLogins = 5;
    private static readonly TimeSpan LockoutDuration = TimeSpan.FromMinutes(15);

    public static void MapAuthEndpoints(this WebApplication app)
    {
        var g = app.MapGroup("/api/auth").WithTags("Auth");

        g.MapPost("/login", LoginAsync).AllowAnonymous().RequireRateLimiting("auth");
        g.MapPost("/refresh", RefreshAsync).AllowAnonymous();
        g.MapPost("/logout", LogoutAsync).AllowAnonymous();
        g.MapGet("/me", MeAsync).AllowAnonymous();
        g.MapPost("/totp/setup", SetupTotpAsync).AllowAnonymous().RequireRateLimiting("auth");
        g.MapPost("/totp/enable", EnableTotpAsync).AllowAnonymous().RequireRateLimiting("auth");
    }

    private static async Task<IResult> LoginAsync(
        LoginRequest req,
        HttpContext http,
        KellaDbContext db,
        OrgContext org,
        IPasswordHasher<User> hasher,
        AuthTokens tokens,
        CancellationToken ct)
    {
        var email = req.Email.Trim().ToLowerInvariant();
        // Login has no organization yet; the email lookup is the only cross-tenant read in auth (CLAUDE.md rule 5).
        var user = await db.Users.IgnoreQueryFilters().FirstOrDefaultAsync(u => u.Email == email, ct);
        if (user is null) return Results.Problem("Email or password is incorrect.", statusCode: 401);

        var now = DateTimeOffset.UtcNow;
        if (user.LockoutUntil > now)
            return Results.Problem("Too many failed attempts. Try again later.", statusCode: 423);

        var verification = hasher.VerifyHashedPassword(user, user.PasswordHash, req.Password);
        if (verification == PasswordVerificationResult.Failed)
        {
            await RecordFailedLoginAsync(db, user, ct);
            return Results.Problem("Email or password is incorrect.", statusCode: 401);
        }
        if (verification == PasswordVerificationResult.SuccessRehashNeeded)
            user.PasswordHash = hasher.HashPassword(user, req.Password);

        if (!string.IsNullOrEmpty(user.TotpSecret))
        {
            if (!Totp.Verify(user.TotpSecret, req.TotpCode, now))
            {
                await RecordFailedLoginAsync(db, user, ct);
                return Results.Problem("Two-factor code is incorrect.", statusCode: 401);
            }
        }
        else if (user.Role is UserRole.Owner or UserRole.Admin)
        {
            var secret = Totp.GenerateSecret();
            return Results.Ok(new LoginResponse(true, tokens.CreateTotpSetupToken(user, secret), null));
        }

        user.FailedLoginCount = 0;
        user.LockoutUntil = null;
        user.UpdatedAt = now;
        db.AuditLog.Add(Audit(user, "auth.login", $"user:{user.Id}"));
        await db.SaveChangesAsync(ct);

        tokens.SetSessionCookies(http.Response, user);
        var orgName = await OrganizationNameAsync(db, user.OrganizationId, ct);
        return Results.Ok(new LoginResponse(false, null, ToDto(user, orgName)));
    }

    private static async Task<IResult> RefreshAsync(
        HttpContext http,
        KellaDbContext db,
        OrgContext org,
        AuthTokens tokens,
        CancellationToken ct)
    {
        http.Request.Cookies.TryGetValue(AuthTokens.RefreshCookie, out var refresh);
        var principal = tokens.Validate(refresh, AuthTokens.RefreshType);
        if (principal is null || !TryUserId(principal, out var userId) || !TryOrgId(principal, out var orgId))
        {
            tokens.ClearSessionCookies(http.Response);
            return Results.Unauthorized();
        }

        org.Set(orgId);
        var user = await db.Users.FirstOrDefaultAsync(u => u.Id == userId, ct);
        if (user is null)
        {
            tokens.ClearSessionCookies(http.Response);
            return Results.Unauthorized();
        }
        if (user.LockoutUntil > DateTimeOffset.UtcNow)
        {
            tokens.ClearSessionCookies(http.Response);
            return Results.Problem("Account is locked.", statusCode: 423);
        }

        tokens.SetSessionCookies(http.Response, user);
        var orgName = await OrganizationNameAsync(db, user.OrganizationId, ct);
        return Results.Ok(ToDto(user, orgName));
    }

    private static async Task<IResult> LogoutAsync(
        HttpContext http,
        KellaDbContext db,
        OrgContext org,
        AuthTokens tokens,
        CancellationToken ct)
    {
        tokens.ClearSessionCookies(http.Response);
        if (http.User.Identity?.IsAuthenticated == true && TryUserId(http.User, out var userId) && org.OrganizationId is not null)
        {
            db.AuditLog.Add(new AuditEntry
            {
                OrganizationId = org.OrganizationId.Value,
                ActorType = "user",
                ActorId = userId.ToString(),
                Verb = "auth.logout",
                Target = $"user:{userId}",
            });
            await db.SaveChangesAsync(ct);
        }
        return Results.NoContent();
    }

    private static async Task<IResult> MeAsync(
        HttpContext http,
        KellaDbContext db,
        OrgContext org,
        DevOrgState dev,
        CancellationToken ct)
    {
        if (http.User.Identity?.IsAuthenticated == true && TryUserId(http.User, out var userId))
        {
            var user = await db.Users.FirstOrDefaultAsync(u => u.Id == userId, ct);
            if (user is null) return Results.Unauthorized();
            return Results.Ok(ToDto(user, await OrganizationNameAsync(db, user.OrganizationId, ct)));
        }

        // Development convenience: report the seeded owner while dashboard login is bypassed.
        if (dev.OrganizationId != Guid.Empty)
        {
            org.Set(dev.OrganizationId);
            var user = await db.Users.OrderBy(u => u.CreatedAt).FirstOrDefaultAsync(ct);
            if (user is not null) return Results.Ok(ToDto(user, await OrganizationNameAsync(db, user.OrganizationId, ct)));
        }

        return Results.Unauthorized();
    }

    private static async Task<IResult> SetupTotpAsync(
        TotpSetupRequest req,
        KellaDbContext db,
        OrgContext org,
        AuthTokens tokens,
        IConfiguration config,
        CancellationToken ct)
    {
        var principal = tokens.Validate(req.SetupToken, AuthTokens.TotpSetupType);
        if (principal is null || !TryUserId(principal, out var userId) || !TryOrgId(principal, out var orgId))
            return Results.Problem("Setup token is invalid or expired.", statusCode: 401);

        var secret = principal.FindFirst("totp")?.Value;
        if (string.IsNullOrEmpty(secret))
            return Results.Problem("Setup token is invalid or expired.", statusCode: 401);

        org.Set(orgId);
        var user = await db.Users.FirstOrDefaultAsync(u => u.Id == userId, ct);
        if (user is null) return Results.Problem("Setup token is invalid or expired.", statusCode: 401);

        var issuer = config["Kella:BrandName"] ?? "Kella";
        return Results.Ok(new TotpSetupResponse(secret, Totp.OtpauthUri(issuer, user.Email, secret)));
    }

    private static async Task<IResult> EnableTotpAsync(
        TotpEnableRequest req,
        HttpContext http,
        KellaDbContext db,
        OrgContext org,
        AuthTokens tokens,
        CancellationToken ct)
    {
        var principal = tokens.Validate(req.SetupToken, AuthTokens.TotpSetupType);
        if (principal is null || !TryUserId(principal, out var userId) || !TryOrgId(principal, out var orgId))
            return Results.Problem("Setup token is invalid or expired.", statusCode: 401);

        var secret = principal.FindFirst("totp")?.Value;
        if (string.IsNullOrEmpty(secret))
            return Results.Problem("Setup token is invalid or expired.", statusCode: 401);

        org.Set(orgId);
        var user = await db.Users.FirstOrDefaultAsync(u => u.Id == userId, ct);
        if (user is null) return Results.Problem("Setup token is invalid or expired.", statusCode: 401);
        if (!string.IsNullOrEmpty(user.TotpSecret))
            return Results.Problem("Two-factor authentication is already enabled.", statusCode: 409);
        if (!Totp.Verify(secret, req.Code, DateTimeOffset.UtcNow))
            return Results.Problem("Two-factor code is incorrect.", statusCode: 401);

        user.TotpSecret = secret;
        user.FailedLoginCount = 0;
        user.LockoutUntil = null;
        user.UpdatedAt = DateTimeOffset.UtcNow;
        db.AuditLog.Add(Audit(user, "auth.totp_enabled", $"user:{user.Id}"));
        await db.SaveChangesAsync(ct);

        tokens.SetSessionCookies(http.Response, user);
        return Results.Ok(ToDto(user, await OrganizationNameAsync(db, user.OrganizationId, ct)));
    }

    private static async Task RecordFailedLoginAsync(KellaDbContext db, User user, CancellationToken ct)
    {
        user.FailedLoginCount++;
        if (user.FailedLoginCount >= MaxFailedLogins)
        {
            user.LockoutUntil = DateTimeOffset.UtcNow.Add(LockoutDuration);
            user.FailedLoginCount = 0;
        }
        user.UpdatedAt = DateTimeOffset.UtcNow;
        db.AuditLog.Add(Audit(user, "auth.login_failed", $"user:{user.Id}"));
        await db.SaveChangesAsync(ct);
    }

    private static AuditEntry Audit(User user, string verb, string target) => new()
    {
        OrganizationId = user.OrganizationId,
        ActorType = "user",
        ActorId = user.Id.ToString(),
        Verb = verb,
        Target = target,
    };

    private static async Task<string> OrganizationNameAsync(KellaDbContext db, Guid organizationId, CancellationToken ct) =>
        await db.Organizations.Where(o => o.Id == organizationId).Select(o => o.Name).FirstAsync(ct);

    private static AuthUserDto ToDto(User user, string organizationName) =>
        new(user.Id, user.Email, user.Name, user.Role.ToString(), user.OrganizationId, organizationName);

    private static bool TryUserId(ClaimsPrincipal principal, out Guid id) =>
        Guid.TryParse(principal.FindFirst("sub")?.Value, out id);

    private static bool TryOrgId(ClaimsPrincipal principal, out Guid id) =>
        Guid.TryParse(principal.FindFirst("org")?.Value, out id);
}
