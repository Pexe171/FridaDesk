using FridaHub.Core.Interfaces;
using System.Threading;
using System.Threading.Tasks;

namespace FridaHub.Processes;

public class FridaVersionChecker : IFridaVersionChecker
{
    private readonly ProcessRunner _runner;
    private string? _cached;

    public FridaVersionChecker(ProcessRunner runner)
    {
        _runner = runner;
    }

    public async Task<string?> GetVersionAsync(CancellationToken cancellationToken = default)
    {
        if (_cached is not null) return _cached;
        try
        {
            var run = _runner.Run("frida", "--version");
            await foreach (var line in run.Output.WithCancellation(cancellationToken))
            {
                _cached = line.Line.Trim();
                break;
            }
            await run.WaitForExitAsync(cancellationToken);
        }
        catch
        {
            _cached = null;
        }
        return _cached;
    }
}
