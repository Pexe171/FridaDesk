using FridaHub.Core.Backends;
using FridaHub.Core.Models;
using FridaHub.Core.Results;

namespace FridaHub.Processes;

/// <summary>
/// Backend que executa o binário do Frida CLI.
/// </summary>
public class FridaService : IFridaBackend
{
    private readonly ProcessRunner _runner;

    public FridaService(ProcessRunner runner)
    {
        _runner = runner;
    }

    // TODO(Jailbreak): implementar suporte futuro de forma segura e autorizada.

    public IAsyncEnumerable<ProcessLine> RunCodeshareAsync(string author, string slug, string package, string? selector = null, CancellationToken cancellationToken = default)
    {
        var args = $"--codeshare {author}/{slug} -f {package} --no-pause";
        if (!string.IsNullOrWhiteSpace(selector))
            args += $" {selector}";
        var run = _runner.Run("frida", args);
        return run.Output;
    }

    public IAsyncEnumerable<ProcessLine> RunLocalScriptAsync(string scriptPath, string package, string? selector = null, CancellationToken cancellationToken = default)
    {
        var args = $"-l {scriptPath} -f {package} --no-pause";
        if (!string.IsNullOrWhiteSpace(selector))
            args += $" {selector}";
        var run = _runner.Run("frida", args);
        return run.Output;
    }

    public async Task<Result<IEnumerable<string>>> ListProcessesAsync(string? deviceSerial = null, CancellationToken cancellationToken = default)
    {
        try
        {
            var deviceArg = string.IsNullOrEmpty(deviceSerial) ? "-U" : $"-D {deviceSerial}";
            var run = _runner.Run("frida-ps", deviceArg);
            var processes = new List<string>();
            await foreach (var line in run.Output.WithCancellation(cancellationToken))
            {
                var text = line.Line.Trim();
                if (string.IsNullOrEmpty(text) || text.StartsWith("PID"))
                    continue;
                var parts = text.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length > 0)
                    processes.Add(parts[^1]);
            }
            var exit = await run.WaitForExitAsync(cancellationToken);
            return exit == 0
                ? Result<IEnumerable<string>>.Success(processes)
                : Result<IEnumerable<string>>.Failure($"frida-ps retornou código {exit}");
        }
        catch (Exception ex)
        {
            return Result<IEnumerable<string>>.Failure(ex.Message);
        }
    }
}

