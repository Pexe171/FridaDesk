using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using FridaHub.Core.Backends;
using FridaHub.Core.Models;
using FridaHub.Core.Results;

namespace FridaHub.FridaCoreBridge;

// Autor: Pexe (instagram David.devloli)
/// <summary>
/// Backend futuro para integração com frida-core.
/// </summary>
public class FridaCoreBackend : IFridaBackend
{
    // TODO: implementar integração com frida-core.
    public async IAsyncEnumerable<ProcessLine> RunCodeshareAsync(string author, string slug, string package, string? selector = null, CancellationToken cancellationToken = default)
    {
        await Task.CompletedTask;
        yield break;
    }

    // TODO: implementar integração com frida-core.
    public async IAsyncEnumerable<ProcessLine> RunLocalScriptAsync(string scriptPath, string package, string? selector = null, CancellationToken cancellationToken = default)
    {
        await Task.CompletedTask;
        yield break;
    }

    // TODO: implementar integração com frida-core.
    public Task<Result<IEnumerable<string>>> ListProcessesAsync(string? deviceSerial = null, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(Result<IEnumerable<string>>.Failure("Não implementado"));
    }
}
