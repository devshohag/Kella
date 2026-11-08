using System.Threading.RateLimiting;
using Kella.Api;
using Kella.Api.Auth;
using Kella.Api.Endpoints;
using Kella.Core.Domain;
using Kella.Infrastructure;
using Kella.Infrastructure.Security;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddKellaInfrastructure(builder.Configuration);
builder.Services.AddProblemDetails();
builder.Services.ConfigureHttpJsonOptions(o =>
    o.SerializerOptions.Converters.Add(new System.Text.Json.Serialization.JsonStringEnumConverter())); // enums as "Succeeded", not 3
builder.Services.AddRequestDecompression(); // agent sends gzip event batches
builder.Services.AddCors(o => o.AddDefaultPolicy(p => p
    .WithOrigins(builder.Configuration.GetSection("Kella:WebOrigins").Get<string[]>() ?? ["http://localhost:5173"])
    .AllowAnyHeader().AllowAnyMethod().AllowCredentials()));

// Auth (SPEC §5, §16). The signing key comes from configuration and must never be committed for production.
var jwt = builder.Configuration.GetSection(JwtOptions.Section).Get<JwtOptions>() ?? new JwtOptions();
jwt.Validate();
builder.Services.AddSingleton(jwt);
builder.Services.AddSingleton<AuthTokens>();
builder.Services.AddSingleton<IPasswordHasher<User>, PasswordHasher<User>>();
builder.Services.AddSingleton<DevOrgState>();

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(o =>
{
    o.MapInboundClaims = false;
    o.TokenValidationParameters = new TokenValidationParameters
    {
        ValidIssuer = jwt.Issuer,
        ValidAudience = jwt.Audience,
        IssuerSigningKey = jwt.SigningKey,
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateIssuerSigningKey = true,
        ValidateLifetime = true,
        ClockSkew = TimeSpan.FromSeconds(30),
        NameClaimType = "name",
    };
    o.Events = new JwtBearerEvents
    {
        OnMessageReceived = ctx =>
        {
            if (string.IsNullOrEmpty(ctx.Token) &&
                ctx.Request.Cookies.TryGetValue(AuthTokens.AccessCookie, out var token))
                ctx.Token = token;
            return Task.CompletedTask;
        },
        OnTokenValidated = ctx =>
        {
            if (ctx.Principal?.FindFirst("typ")?.Value != AuthTokens.AccessType)
                ctx.Fail("Not an access token.");
            return Task.CompletedTask;
        },
    };
});
builder.Services.AddAuthorization();

builder.Services.AddRateLimiter(o =>
{
    o.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    var permitLimit = builder.Configuration.GetValue("Kella:RateLimits:AuthPermitLimit", 10);
    o.AddPolicy("auth", ctx => RateLimitPartition.GetFixedWindowLimiter(
        ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
        _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = permitLimit,
            Window = TimeSpan.FromMinutes(1),
            QueueLimit = 0,
        }));
});

// Single-process mode: run the rule engine inside the API (default in Development).
if (builder.Configuration.GetValue("Kella:RunPipelineInApi", builder.Environment.IsDevelopment()))
    builder.Services.AddKellaPipeline();

var app = builder.Build();

// Eagerly validate command signing key at startup (SPEC §8.5, §16)
app.Services.GetRequiredService<CommandSigner>();

var devMode = app.Environment.IsDevelopment() || app.Environment.IsEnvironment("Testing");
var devBypass = devMode && app.Configuration.GetValue("Kella:DevOrg:Enabled", true);

await DatabaseSeeder.InitializeAsync(app, devBypass);

app.UseExceptionHandler();
app.UseRequestDecompression();
app.UseCors();
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();

// Every authenticated request runs as the organization in its token; the EF query filter enforces isolation.
app.Use(async (ctx, next) =>
{
    if (ctx.User.Identity?.IsAuthenticated == true)
    {
        var orgClaim = ctx.User.FindFirst("org")?.Value;
        if (Guid.TryParse(orgClaim, out var organizationId))
            ctx.RequestServices.GetRequiredService<OrgContext>().Set(organizationId);
    }
    await next();
});

if (devBypass)
{
    app.UseDevOrg();
    app.Logger.LogWarning(
        "Development mode: dashboard runs as the demo organization without login. Enrollment key: {Key}",
        DatabaseSeeder.DevEnrollmentKey);
}

app.MapGet("/health", () => Results.Ok(new { status = "ok" })).AllowAnonymous();
app.MapAuthEndpoints();
app.MapAgentEndpoints();
app.MapDashboardEndpoints(requireAuth: !devBypass);
app.MapWebhookEndpoints();

app.Run();

public partial class Program;
