using FridaDesk.Core.Backends;
using FridaDesk.Core.Models;
using FridaDesk.Core.Results;

namespace FridaDesk.Processes;

/// <summary>
/// Backend Frida com resultados fictícios.
/// </summary>
public class FridaService : IFridaBackend
{
    private readonly ProcessRunner _runner;

    public FridaService(ProcessRunner runner)
    {
        _runner = runner;
    }

    public IAsyncEnumerable<ProcessLine> RunCodeshareAsync(string author, string slug, string package, string? selector = null, CancellationToken cancellationToken = default)
    {
        return GetMockOutput();
    }

    public IAsyncEnumerable<ProcessLine> RunLocalScriptAsync(string scriptPath, string package, string? selector = null, CancellationToken cancellationToken = default)
    {
        return GetMockOutput();
    }

    public Task<Result<IEnumerable<string>>> ListProcessesAsync(string? deviceSerial = null, CancellationToken cancellationToken = default)
    {
        IEnumerable<string> processes = new[] { "com.example.app" };
        return Task.FromResult(Result<IEnumerable<string>>.Success(processes));
    }

    private async IAsyncEnumerable<ProcessLine> GetMockOutput()
    {
        yield return new ProcessLine(DateTime.UtcNow, false, "stub");
        await Task.CompletedTask;
    }
}
