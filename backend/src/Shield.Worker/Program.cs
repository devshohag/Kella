using Shield.Infrastructure;

// Shield.Worker hosts the event consumers (rule engine, playbooks, alerts, AI) as a separate process.
// Until NatsEventBus exists (Phase 1), events only flow inside one process, so in development run the
// pipeline inside the API instead (Shield:RunPipelineInApi = true, the default in Development).
var builder = Host.CreateApplicationBuilder(args);

builder.Services.AddShieldInfrastructure(builder.Configuration);
builder.Services.AddShieldPipeline();

var host = builder.Build();
host.Run();
