using System.Runtime.CompilerServices;
using System.Threading.Channels;
using Shield.Core;
using Shield.Core.Domain;

namespace Shield.Infrastructure.Pipeline;

/// <summary>
/// Single-process event bus for development and Phase 0/1. Bounded so a flood cannot exhaust memory.
/// TODO(Phase 1): add NatsEventBus implementing <see cref="IEventBus"/> on JetStream subject "shield.events".
/// </summary>
public sealed class InProcessEventBus : IEventBus
{
    private readonly Channel<ShieldEvent> _channel = Channel.CreateBounded<ShieldEvent>(
        new BoundedChannelOptions(100_000) { FullMode = BoundedChannelFullMode.DropOldest, SingleReader = true });

    public ValueTask PublishAsync(ShieldEvent evt, CancellationToken ct) => _channel.Writer.WriteAsync(evt, ct);

    public async IAsyncEnumerable<ShieldEvent> SubscribeAsync([EnumeratorCancellation] CancellationToken ct)
    {
        await foreach (var evt in _channel.Reader.ReadAllAsync(ct))
            yield return evt;
    }
}
