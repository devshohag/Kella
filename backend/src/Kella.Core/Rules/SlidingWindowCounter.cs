using System.Collections.Concurrent;

namespace Kella.Core.Rules;

/// <summary>
/// Counts occurrences per key within a time window. In-memory, single node.
/// TODO(Phase 2): move to the Signal Aggregator with persistence so restarts do not reset counts.
/// </summary>
public sealed class SlidingWindowCounter(TimeSpan window)
{
    private readonly ConcurrentDictionary<string, Queue<DateTimeOffset>> _hits = new();

    public int Add(string key, DateTimeOffset at)
    {
        var q = _hits.GetOrAdd(key, _ => new Queue<DateTimeOffset>());
        lock (q)
        {
            q.Enqueue(at);
            while (q.Count > 0 && at - q.Peek() > window)
                q.Dequeue();
            return q.Count;
        }
    }

    public int Count(string key, DateTimeOffset at)
    {
        if (!_hits.TryGetValue(key, out var q)) return 0;
        lock (q)
        {
            while (q.Count > 0 && at - q.Peek() > window)
                q.Dequeue();
            return q.Count;
        }
    }

    public void Reset(string key) => _hits.TryRemove(key, out _);
}
