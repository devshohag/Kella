using System.Net.Http.Json;
using System.Text.Json;
using Kella.Core;
using Kella.Core.Domain;

namespace Kella.Infrastructure.Alerting;

/// <summary>Sends incident alerts through the Telegram Bot API (SPEC §12).</summary>
public sealed class TelegramAlertChannel : IAlertChannel, IDisposable
{
    private readonly TelegramOptions _options;
    private readonly HttpClient _http;

    public TelegramAlertChannel(TelegramOptions options)
        : this(options, new HttpClientHandler())
    {
    }

    public TelegramAlertChannel(TelegramOptions options, HttpMessageHandler handler)
    {
        _options = options;
        _http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(Math.Max(1, options.TimeoutSeconds)) };
    }

    public AlertChannelKind Kind => AlertChannelKind.Telegram;

    public async Task SendAsync(User recipient, AlertMessage message, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(_options.BotToken))
            throw new InvalidOperationException("Telegram bot token is not configured (Kella:Telegram:BotToken).");
        if (string.IsNullOrWhiteSpace(recipient.TelegramChatId))
            throw new InvalidOperationException("Recipient has no Telegram chat id.");

        var url = $"{_options.ApiBase.TrimEnd('/')}/bot{_options.BotToken}/sendMessage";
        var body = new Dictionary<string, object>
        {
            ["chat_id"] = recipient.TelegramChatId,
            ["text"] = Format(message),
            ["disable_web_page_preview"] = true,
        };

        using var response = await _http.PostAsJsonAsync(url, body, ct);
        if (!response.IsSuccessStatusCode)
        {
            var detail = await response.Content.ReadAsStringAsync(ct);
            throw new HttpRequestException($"Telegram returned {(int)response.StatusCode}: {Truncate(detail, 300)}");
        }

        await using var stream = await response.Content.ReadAsStreamAsync(ct);
        using var json = await JsonDocument.ParseAsync(stream, cancellationToken: ct);
        if (!json.RootElement.TryGetProperty("ok", out var ok) || !ok.GetBoolean())
            throw new HttpRequestException("Telegram rejected the message.");
    }

    public static string Format(AlertMessage message)
    {
        var icon = message.Severity switch
        {
            Severity.Down => "🔴",
            Severity.Critical => "🔴",
            Severity.Warning => "🟠",
            _ => "ℹ️",
        };
        var text = $"{icon} {message.Severity}: {message.Title}\n{message.Body}";
        if (message.ReplyOptions.Count > 0)
            text += "\n\n" + string.Join('\n', message.ReplyOptions.Select((r, i) => $"Reply {i + 1} to {r}"));
        return text.Trim();
    }

    private static string Truncate(string value, int max) => value.Length <= max ? value : value[..max];

    public void Dispose() => _http.Dispose();
}
