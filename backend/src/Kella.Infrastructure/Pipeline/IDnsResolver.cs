using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace Kella.Infrastructure.Pipeline;

public interface IDnsResolver
{
    /// <summary>
    /// Resolves DNS query.
    /// Returns IP addresses if resolved.
    /// Returns empty array on NXDOMAIN (not found / not listed).
    /// Returns null on network / server failure / timeout (unknown state).
    /// </summary>
    Task<IPAddress[]?> ResolveAsync(string query, CancellationToken ct = default);
}

public sealed class SystemDnsResolver : IDnsResolver
{
    public async Task<IPAddress[]?> ResolveAsync(string query, CancellationToken ct = default)
    {
        try
        {
            var entry = await Dns.GetHostEntryAsync(query, ct);
            return entry.AddressList;
        }
        catch (SocketException ex) when (ex.SocketErrorCode is SocketError.HostNotFound or SocketError.NoData)
        {
            // NXDOMAIN -> not listed
            return Array.Empty<IPAddress>();
        }
        catch
        {
            // Transient network failure or resolver refused -> unknown
            return null;
        }
    }
}
