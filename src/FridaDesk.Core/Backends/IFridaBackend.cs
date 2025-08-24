using FridaDesk.Core.Models;
using FridaDesk.Core.Results;

namespace FridaDesk.Core.Backends;

public interface IFridaBackend
{
    /// <summary>
    /// Executa um script do Codeshare e retorna um fluxo das linhas produzidas.
    /// </summary>
    IAsyncEnumerable<ProcessLine> RunCodeshareAsync(string author, string slug, string package, string? selector = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Executa um script local e retorna um fluxo das linhas produzidas.
    /// </summary>
    IAsyncEnumerable<ProcessLine> RunLocalScriptAsync(string scriptPath, string package, string? selector = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Lista os processos disponíveis através do utilitário frida-ps.
    /// </summary>
    Task<Result<IEnumerable<string>>> ListProcessesAsync(string? deviceSerial = null, CancellationToken cancellationToken = default);
}

