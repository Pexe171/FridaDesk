using System.Diagnostics;
using System.Threading.Channels;
using FridaHub.Core.Models;

namespace FridaHub.Processes;

/// <summary>
/// Executa binários externos e expõe as linhas produzidas via <see cref="IAsyncEnumerable{T}"/>.
/// </summary>
public class ProcessRunner
{
    /// <summary>
    /// Inicia o processo e retorna um <see cref="ProcessRun"/> que permite acompanhar a saída.
    /// </summary>
    public ProcessRun Run(string fileName, string arguments = "")
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = fileName,
            Arguments = arguments,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };

        var process = new Process { StartInfo = startInfo, EnableRaisingEvents = true };
        var channel = Channel.CreateUnbounded<ProcessLine>();

        process.OutputDataReceived += (_, e) =>
        {
            if (e.Data != null)
                channel.Writer.TryWrite(new ProcessLine(DateTime.UtcNow, false, e.Data));
        };

        process.ErrorDataReceived += (_, e) =>
        {
            if (e.Data != null)
                channel.Writer.TryWrite(new ProcessLine(DateTime.UtcNow, true, e.Data));
        };

        process.Start();
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();

        _ = Task.Run(async () =>
        {
            await process.WaitForExitAsync();
            channel.Writer.TryComplete();
        });

        return new ProcessRun(process, channel.Reader);
    }
}

/// <summary>
/// Resultado da execução de um processo externo.
/// </summary>
public class ProcessRun
{
    private readonly Process _process;
    private readonly ChannelReader<ProcessLine> _reader;

    internal ProcessRun(Process process, ChannelReader<ProcessLine> reader)
    {
        _process = process;
        _reader = reader;
    }

    /// <summary>Fluxo assíncrono de linhas produzidas pelo processo.</summary>
    public IAsyncEnumerable<ProcessLine> Output => _reader.ReadAllAsync();

    /// <summary>Espera a finalização do processo e retorna o código de saída.</summary>
    public async Task<int> WaitForExitAsync(CancellationToken cancellationToken = default)
    {
        await _process.WaitForExitAsync(cancellationToken);
        return _process.ExitCode;
    }
}

