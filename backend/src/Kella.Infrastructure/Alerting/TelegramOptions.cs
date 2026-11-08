using Kella.Core.Domain;
using Microsoft.Extensions.Configuration;

namespace Kella.Infrastructure.Alerting;

public sealed class TelegramOptions
{
    public string? BotToken { get; set; }
    /// <summary>Override for tests and local stubs; defaults to the real Bot API.</summary>
    public string ApiBase { get; set; } = "https://api.telegram.org";
    public int TimeoutSeconds { get; set; } = 10;
}

public static class AlertSettings
{
    public static TelegramOptions Telegram(IConfiguration config) =>
        config.GetSection("Kella:Telegram").Get<TelegramOptions>() ?? new TelegramOptions();
}
