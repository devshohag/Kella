namespace Kella.Core.Domain;

/// <summary>Every organization-owned row implements this so the DbContext can filter by organization.</summary>
public interface IOrgScoped
{
    Guid OrganizationId { get; set; }
}

public abstract class Entity
{
    public Guid Id { get; set; } = Guid.CreateVersion7();
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;
}

public sealed class Organization : Entity
{
    public required string Name { get; set; }
    public string Plan { get; set; } = "free";
    public string Language { get; set; } = "en";
    public Dictionary<string, string> Settings { get; set; } = [];
}

public enum UserRole { Owner, Admin, Responder, Viewer }

public sealed class User : Entity, IOrgScoped
{
    public Guid OrganizationId { get; set; }
    public required string Email { get; set; }
    public required string Name { get; set; }
    public string PasswordHash { get; set; } = "";
    public UserRole Role { get; set; } = UserRole.Viewer;
    /// <summary>Base32 TOTP secret. Null until the user completes two-factor setup.</summary>
    public string? TotpSecret { get; set; }
    public int FailedLoginCount { get; set; }
    public DateTimeOffset? LockoutUntil { get; set; }
    public string? Phone { get; set; }
    public string? TelegramChatId { get; set; }
}

public enum ServerStatus { Pending, Online, Offline, Disabled }

public sealed class Server : Entity, IOrgScoped
{
    public Guid OrganizationId { get; set; }
    public required string Name { get; set; }
    public string Hostname { get; set; } = "";
    public string? PublicIp { get; set; }
    public string Os { get; set; } = "";
    public int CpuCount { get; set; }
    public int RamMb { get; set; }
    public string AgentVersion { get; set; } = "";
    /// <summary>SHA-256 hex of the agent token. The token itself is never stored.</summary>
    public string KeyHash { get; set; } = "";
    public ServerStatus Status { get; set; } = ServerStatus.Pending;
    public DateTimeOffset? LastSeenAt { get; set; }
    public List<string> Detected { get; set; } = [];
    public List<string> Guards { get; set; } = [];
}

public sealed class EnrollmentKey : Entity, IOrgScoped
{
    public Guid OrganizationId { get; set; }
    public required string KeyHash { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public int UsesLeft { get; set; } = 1;
}

public sealed class Tenant : Entity, IOrgScoped
{
    public Guid OrganizationId { get; set; }
    public required string Name { get; set; }
    public string? ExternalRef { get; set; }
    public string? ContactEmail { get; set; }
    public string? ContactPhone { get; set; }
    public string Plan { get; set; } = "free";
    public string Status { get; set; } = "active";
}

public enum AssetKind { Domain, Mailbox, Site, SipTrunk, Database, Container }

public sealed class Asset : Entity, IOrgScoped
{
    public Guid OrganizationId { get; set; }
    public Guid TenantId { get; set; }
    public Guid? ServerId { get; set; }
    public AssetKind Kind { get; set; }
    /// <summary>e.g. "rahmantraders.com", "billing@rahmantraders.com", "shop.example.com".</summary>
    public required string Identifier { get; set; }
    public Dictionary<string, string> Meta { get; set; } = [];
}

public enum Severity { Info, Warning, Critical, Down }

public sealed class KellaEvent : IOrgScoped
{
    public Guid Id { get; set; } = Guid.CreateVersion7();
    public Guid OrganizationId { get; set; }
    public Guid ServerId { get; set; }
    public Guid? TenantId { get; set; }
    public Guid? AssetId { get; set; }
    public DateTimeOffset Ts { get; set; }
    public required string Module { get; set; }
    public required string Type { get; set; }
    public Severity Severity { get; set; }
    public string? SourceIp { get; set; }
    public Dictionary<string, string> Attrs { get; set; } = [];
}

public enum IncidentStatus { Open, Contained, Resolved }

public sealed class Incident : Entity, IOrgScoped
{
    public Guid OrganizationId { get; set; }
    public int Number { get; set; }
    public Guid? TenantId { get; set; }
    public Guid? ServerId { get; set; }
    public required string Type { get; set; }
    public Severity Severity { get; set; }
    public IncidentStatus Status { get; set; } = IncidentStatus.Open;
    public required string Title { get; set; }
    public string Summary { get; set; } = "";
    public DateTimeOffset OpenedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? ContainedAt { get; set; }
    public DateTimeOffset? ResolvedAt { get; set; }
    public DateTimeOffset? AcknowledgedAt { get; set; }
    public string? AcknowledgedBy { get; set; }
    public string? AiAnalysisJson { get; set; }
}

public sealed class Finding : Entity, IOrgScoped
{
    public Guid OrganizationId { get; set; }
    public required string RuleCode { get; set; }
    public Guid? TenantId { get; set; }
    public Guid ServerId { get; set; }
    public Severity Severity { get; set; }
    public required string Title { get; set; }
    public string Summary { get; set; } = "";
    public Dictionary<string, string> Evidence { get; set; } = [];
    public DateTimeOffset FirstSeen { get; set; }
    public DateTimeOffset LastSeen { get; set; }
    public Guid? IncidentId { get; set; }
}

public enum ActionMode { Auto, Approval }

public enum ActionStatus { PendingApproval, Queued, Sent, Succeeded, Failed, Rejected, Expired, Reverted }

public sealed class KellaAction : Entity, IOrgScoped
{
    public Guid OrganizationId { get; set; }
    public Guid? IncidentId { get; set; }
    public Guid ServerId { get; set; }
    /// <summary>One of <see cref="Kella.Core.Actions.ActionKinds"/>.</summary>
    public required string Kind { get; set; }
    public Dictionary<string, string> Params { get; set; } = [];
    public ActionMode Mode { get; set; }
    public ActionStatus Status { get; set; }
    public string? Label { get; set; }
    public string RequestedBy { get; set; } = "system";
    public string? ApprovedBy { get; set; }
    public DateTimeOffset? ExpiresAt { get; set; }
    public DateTimeOffset? ExecutedAt { get; set; }
    public string? ResultJson { get; set; }
}

public sealed class AgentCommand : Entity
{
    public Guid ServerId { get; set; }
    public Guid ActionId { get; set; }
    /// <summary>JSON payload (SPEC §6): kind, params and expiresAt. Signed as a whole in Phase 1.</summary>
    public string Payload { get; set; } = "{}";
    public string Signature { get; set; } = "";
    public string Status { get; set; } = "queued";
    public DateTimeOffset? FetchedAt { get; set; }
    public DateTimeOffset? AckedAt { get; set; }
}

public sealed class Rule : Entity
{
    /// <summary>Null for built-in rules; set when an organization overrides one.</summary>
    public Guid? OrganizationId { get; set; }
    public required string Code { get; set; }
    public bool Enabled { get; set; } = true;
    public Dictionary<string, string> Params { get; set; } = [];
}

public sealed class AlertRoute : Entity, IOrgScoped
{
    public Guid OrganizationId { get; set; }
    public Severity Severity { get; set; }
    /// <summary>One or more of email, telegram, whatsapp, voice, dashboard.</summary>
    public List<string> Channels { get; set; } = [];
}

public sealed class AlertDelivery : Entity, IOrgScoped
{
    public Guid OrganizationId { get; set; }
    public Guid IncidentId { get; set; }
    public required string Channel { get; set; }
    public required string Recipient { get; set; }
    public string Status { get; set; } = "pending";
    public DateTimeOffset? SentAt { get; set; }
    public string? Reply { get; set; }
}

/// <summary>Rolling hourly percentiles per entity (SPEC §9).</summary>
public sealed class Baseline : Entity, IOrgScoped
{
    public Guid OrganizationId { get; set; }
    public required string EntityKind { get; set; }
    public required string EntityId { get; set; }
    /// <summary>0 = Monday 00:00 … 167 = Sunday 23:00, in UTC.</summary>
    public int HourOfWeek { get; set; }
    public double P50 { get; set; }
    public double P95 { get; set; }
}

public sealed class AuditEntry : IOrgScoped
{
    public Guid Id { get; set; } = Guid.CreateVersion7();
    public Guid OrganizationId { get; set; }
    public required string ActorType { get; set; }
    public required string ActorId { get; set; }
    public required string Verb { get; set; }
    public required string Target { get; set; }
    public string? DataJson { get; set; }
    public DateTimeOffset Ts { get; set; } = DateTimeOffset.UtcNow;
}

public sealed class TelegramUpdate
{
    public long UpdateId { get; set; }
    public DateTimeOffset ProcessedAt { get; set; } = DateTimeOffset.UtcNow;
}

public sealed class IpReputation : Entity, IOrgScoped
{
    public Guid OrganizationId { get; set; }
    public Guid ServerId { get; set; }
    public required string Ip { get; set; }
    public bool Listed { get; set; }
    public string? ReturnCode { get; set; }
    public DateTimeOffset? ListedSince { get; set; }
    public DateTimeOffset LastChecked { get; set; } = DateTimeOffset.UtcNow;
}
