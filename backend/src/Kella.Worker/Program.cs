using Kella.Infrastructure;

// Kella.Worker hosts the event consumers (rule engine, playbooks, alerts, AI) as a separate process.
// Until NatsEventBus exists (Phase 1), events only flow inside one process, so in development run the
// pipeline inside the API instead (Kella:RunPipelineInApi = true, the default in Development).
var builder = Host.CreateApplicationBuilder(args);

builder.Services.AddKellaInfrastructure(builder.Configuration);
builder.Services.AddKellaPipeline();

var host = builder.Build();
host.Run();
