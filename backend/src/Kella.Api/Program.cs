using Kella.Api;
using Kella.Api.Endpoints;
using Kella.Infrastructure;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddKellaInfrastructure(builder.Configuration);
builder.Services.AddProblemDetails();
builder.Services.ConfigureHttpJsonOptions(o =>
    o.SerializerOptions.Converters.Add(new System.Text.Json.Serialization.JsonStringEnumConverter())); // enums as "Succeeded", not 3
builder.Services.AddRequestDecompression(); // agent sends gzip event batches
builder.Services.AddCors(o => o.AddDefaultPolicy(p => p
    .WithOrigins(builder.Configuration.GetSection("Kella:WebOrigins").Get<string[]>() ?? ["http://localhost:5173"])
    .AllowAnyHeader().AllowAnyMethod().AllowCredentials()));

// Single-process mode: run the rule engine inside the API (default in Development).
if (builder.Configuration.GetValue("Kella:RunPipelineInApi", builder.Environment.IsDevelopment()))
    builder.Services.AddKellaPipeline();

var app = builder.Build();

app.UseExceptionHandler();
app.UseRequestDecompression();
app.UseCors();

if (app.Environment.IsDevelopment() || app.Environment.IsEnvironment("Testing"))
{
    await DevSeed.RunAsync(app.Services);
    app.UseDevOrg();
    app.Logger.LogWarning("Development mode: dashboard runs as the demo organization without login. Enrollment key: {Key}", DevSeed.DevEnrollmentKey);
}

app.MapGet("/health", () => Results.Ok(new { status = "ok" }));
app.MapAgentEndpoints();
app.MapDashboardEndpoints();

app.Run();

public partial class Program;
