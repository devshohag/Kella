namespace Kella.Core.Events;

/// <summary>Stable event type names. These are an API contract (SPEC §7) — never rename.</summary>
public static class EventTypes
{
    public const string ServerHeartbeat = "server.heartbeat";
    public const string SshAuthFailed = "server.ssh_auth_failed";
    public const string SshAuthSucceeded = "server.ssh_auth_succeeded";
    public const string ServiceDown = "server.service_down";
    public const string ServiceUp = "server.service_up";
    public const string PackageUpdates = "server.package_updates";

    public const string MailAuthFailed = "mail.auth_failed";
    public const string MailAuthSucceeded = "mail.auth_succeeded";
    public const string MailMessageQueued = "mail.message_queued";
    public const string MailQueueSize = "mail.queue_size";

    public const string WebRequestSummary = "web.request_summary";

    public const string VoiceSipAuthFailed = "voice.sip_auth_failed";
    public const string VoiceCallStarted = "voice.call_started";
}

public static class Modules
{
    public const string Server = "server";
    public const string Mail = "mail";
    public const string Web = "web";
    public const string Voice = "voice";
}
