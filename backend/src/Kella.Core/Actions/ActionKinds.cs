namespace Kella.Core.Actions;

/// <summary>Agent command kinds (SPEC §8.5). Keep in sync with agent/internal/actuators.</summary>
public static class ActionKinds
{
    public const string BlockIp = "block_ip";
    public const string UnblockIp = "unblock_ip";
    public const string HoldSender = "hold_sender";
    public const string ReleaseSender = "release_sender";
    public const string ResetMailboxPassword = "reset_mailbox_password";
    public const string DeleteHeldMessages = "delete_held_messages";
    public const string CapSiteCpu = "cap_site_cpu";
    public const string RunCheck = "run_check";

    public static readonly IReadOnlySet<string> All = new HashSet<string>
    {
        BlockIp, UnblockIp, HoldSender, ReleaseSender, ResetMailboxPassword, DeleteHeldMessages, CapSiteCpu, RunCheck,
    };
}
