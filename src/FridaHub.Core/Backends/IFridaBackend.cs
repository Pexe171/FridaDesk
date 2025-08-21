using FridaHub.Core.Models;
using FridaHub.Core.Results;

namespace FridaHub.Core.Backends;

public interface IFridaBackend
{
    Task<Result<IEnumerable<string>>> ListProcesses(string deviceSerial);
    Task<Result<RunRecord>> RunCodeshareAsync(string deviceSerial, string slug);
    Task<Result<RunRecord>> RunLocalScriptAsync(string deviceSerial, string scriptPath);
}
