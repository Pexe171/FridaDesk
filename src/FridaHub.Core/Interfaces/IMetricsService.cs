using FridaHub.Core.Models;

namespace FridaHub.Core.Interfaces;

public interface IMetricsService
{
    Metrics Current { get; }
    void IncrementRuns();
    void IncrementRunErrors();
    void RecordAdbLatency(TimeSpan latency);
}
