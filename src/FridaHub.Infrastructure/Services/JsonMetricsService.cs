using System.Text.Json;
using FridaHub.Core.Interfaces;
using FridaHub.Core.Models;

namespace FridaHub.Infrastructure.Services;

public class JsonMetricsService : IMetricsService
{
    private readonly string _filePath;
    public Metrics Current { get; private set; } = new();

    public JsonMetricsService(string? filePath = null)
    {
        if (string.IsNullOrWhiteSpace(filePath))
        {
            var baseDir = OperatingSystem.IsWindows()
                ? Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)
                : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".local", "share");
            var appDir = Path.Combine(baseDir, "FridaHub");
            Directory.CreateDirectory(appDir);
            _filePath = Path.Combine(appDir, "metrics.json");
        }
        else
        {
            _filePath = filePath;
            var dir = Path.GetDirectoryName(_filePath)!;
            Directory.CreateDirectory(dir);
        }

        LoadAsync().GetAwaiter().GetResult();
    }

    public void IncrementRuns()
    {
        Current.RunsTotal++;
        SaveAsync().GetAwaiter().GetResult();
    }

    public void IncrementRunErrors()
    {
        Current.RunErrorsTotal++;
        SaveAsync().GetAwaiter().GetResult();
    }

    public void RecordAdbLatency(TimeSpan latency)
    {
        var ms = latency.TotalMilliseconds;
        Current.AdbLatencyMsAvg =
            (Current.AdbLatencyMsAvg * Current.AdbLatencySamples + ms) / (++Current.AdbLatencySamples);
        SaveAsync().GetAwaiter().GetResult();
    }

    private async Task LoadAsync()
    {
        if (!File.Exists(_filePath))
            return;

        await using var stream = File.OpenRead(_filePath);
        var metrics = await JsonSerializer.DeserializeAsync<Metrics>(stream);
        if (metrics != null)
            Current = metrics;
    }

    private async Task SaveAsync()
    {
        var dir = Path.GetDirectoryName(_filePath)!;
        Directory.CreateDirectory(dir);
        await using var stream = File.Create(_filePath);
        await JsonSerializer.SerializeAsync(stream, Current, new JsonSerializerOptions { WriteIndented = true });
    }
}
