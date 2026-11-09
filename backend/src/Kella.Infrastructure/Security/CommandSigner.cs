using System.Globalization;
using System.Text;
using Kella.Core.Actions;
using Kella.Core.Domain;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace Kella.Infrastructure.Security;

/// <summary>
/// Signs agent commands with Ed25519 (SPEC §8.5, §16). The agent verifies the signature over
/// <see cref="CanonicalPayload"/> with the public key it received at enrollment.
/// </summary>
public sealed class CommandSigner
{
    private readonly Ed25519PrivateKeyParameters _privateKey;

    public CommandSigner(IConfiguration config, IHostEnvironment? env = null)
    {
        var isDev = env?.IsDevelopment() == true;
        var raw = config["Kella:Commands:PrivateKey"];

        if (string.IsNullOrWhiteSpace(raw))
        {
            throw new InvalidOperationException(
                "Kella:Commands:PrivateKey is required (base64 Ed25519 seed). Set KELLA__COMMANDS__PRIVATEKEY.");
        }

        byte[] decoded;
        try { decoded = Convert.FromBase64String(raw); }
        catch (FormatException) { throw new InvalidOperationException("Kella:Commands:PrivateKey is not valid base64."); }

        // Accept either the 32-byte seed (what we document) or Go's 64-byte private key.
        if (decoded.Length == 64) decoded = decoded[..32];
        if (decoded.Length != Ed25519PrivateKeyParameters.KeySize)
            throw new InvalidOperationException("Kella:Commands:PrivateKey must be a 32-byte Ed25519 seed.");

        if (!isDev && decoded.All(b => b == 0))
        {
            throw new InvalidOperationException(
                "Kella:Commands:PrivateKey cannot be the all-zero seed in production. Set a secure key.");
        }

        _privateKey = new Ed25519PrivateKeyParameters(decoded, 0);
        PublicKeyBase64 = Convert.ToBase64String(_privateKey.GeneratePublicKey().GetEncoded());
    }

    public string PublicKeyBase64 { get; }

    /// <summary>id|kind|expiresAt(RFC3339, whole seconds)|k1=v1&amp;k2=v2 with ordinal-sorted keys.</summary>
    public static string CanonicalPayload(
        Guid id, string kind, IReadOnlyDictionary<string, string> parameters, DateTimeOffset expiresAt)
    {
        var pairs = parameters
            .OrderBy(p => p.Key, StringComparer.Ordinal)
            .Select(p => $"{p.Key}={p.Value}");
        var timestamp = expiresAt.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);
        return $"{id}|{kind}|{timestamp}|{string.Join('&', pairs)}";
    }

    public string Sign(Guid id, string kind, IReadOnlyDictionary<string, string> parameters, DateTimeOffset expiresAt)
    {
        var message = Encoding.UTF8.GetBytes(CanonicalPayload(id, kind, parameters, expiresAt));
        var signer = new Ed25519Signer();
        signer.Init(true, _privateKey);
        signer.BlockUpdate(message, 0, message.Length);
        return Convert.ToBase64String(signer.GenerateSignature());
    }

    public static bool Verify(string publicKeyBase64, string canonicalPayload, string signatureBase64)
    {
        var publicKey = new Ed25519PublicKeyParameters(Convert.FromBase64String(publicKeyBase64), 0);
        var message = Encoding.UTF8.GetBytes(canonicalPayload);
        var verifier = new Ed25519Signer();
        verifier.Init(false, publicKey);
        verifier.BlockUpdate(message, 0, message.Length);
        return verifier.VerifySignature(Convert.FromBase64String(signatureBase64));
    }
}

public static class AgentCommands
{
    /// <summary>Builds a queued command with a signed payload (SPEC §6, §8.5).</summary>
    public static AgentCommand Queue(
        CommandSigner signer,
        Guid serverId,
        Guid actionId,
        string kind,
        IReadOnlyDictionary<string, string> parameters,
        DateTimeOffset expiresAt)
    {
        var copy = new Dictionary<string, string>(parameters, StringComparer.Ordinal);
        var command = new AgentCommand
        {
            ServerId = serverId,
            ActionId = actionId,
            Payload = AgentCommandPayloadJson.Serialize(
                new AgentCommandPayload(kind, copy, expiresAt)),
        };
        command.Signature = signer.Sign(command.Id, kind, copy, expiresAt);
        return command;
    }
}
