namespace FridaHub.Core.Models;

/// <summary>
/// Métricas locais simples gravadas em arquivo.
/// </summary>
public class Metrics
{
    public int RunsTotal { get; set; }
    public int RunErrorsTotal { get; set; }
    public double AdbLatencyMsAvg { get; set; }
    public int AdbLatencySamples { get; set; }
}
