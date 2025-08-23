using FridaHub.Infrastructure.Services;

namespace FridaHub.Tests;

public class JsonMetricsServiceTests
{
    [Fact]
    public void DevePersistirMetricas()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        var file = Path.Combine(tempDir, "metrics.json");
        var service = new JsonMetricsService(file);

        service.IncrementRuns();
        service.IncrementRunErrors();
        service.RecordAdbLatency(TimeSpan.FromMilliseconds(100));

        var runs = service.Current.RunsTotal;
        var errors = service.Current.RunErrorsTotal;
        var avg = service.Current.AdbLatencyMsAvg;

        var service2 = new JsonMetricsService(file);
        Assert.Equal(runs, service2.Current.RunsTotal);
        Assert.Equal(errors, service2.Current.RunErrorsTotal);
        Assert.Equal(avg, service2.Current.AdbLatencyMsAvg);
    }
}
