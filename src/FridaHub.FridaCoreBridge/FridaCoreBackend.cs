using FridaHub.Core.Backends;
using FridaHub.Core.Models;
using FridaHub.Core.Results;

// Autor: Pexe (instagram David.devloli)
namespace FridaHub.FridaCoreBridge;

// TODO: implementar integração com frida-core
public class FridaCoreBackend : IFridaBackend
{
    // TODO: conectar com frida-core (Gadget/JB futuro)
    public IAsyncEnumerable<ProcessLine> RunCodeshareAsync(string author, string slug, string package, string? selector = null,
        CancellationToken cancellationToken = default) => throw new NotImplementedException();

    // TODO: conectar com frida-core (Gadget/JB futuro)
    public IAsyncEnumerable<ProcessLine> RunLocalScriptAsync(string scriptPath, string package, string? selector = null,
        CancellationToken cancellationToken = default) => throw new NotImplementedException();

    // TODO: conectar com frida-core (Gadget/JB futuro)
    public Task<Result<IEnumerable<string>>> ListProcessesAsync(string? deviceSerial = null,
        CancellationToken cancellationToken = default) => Task.FromResult(Result<IEnumerable<string>>.Failure("TODO"));
}

