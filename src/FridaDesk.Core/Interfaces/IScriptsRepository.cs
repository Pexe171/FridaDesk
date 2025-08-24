using FridaDesk.Core.Models;
using FridaDesk.Core.Results;

namespace FridaDesk.Core.Interfaces;

public interface IScriptsRepository
{
    Task<Result<ScriptRef>> GetAsync(Guid id);
    Task<Result<IEnumerable<ScriptRef>>> SearchAsync(string query);
    Task<Result> AddAsync(ScriptRef script);
    Task<Result> UpdateAsync(ScriptRef script);
    Task<Result> DeleteAsync(Guid id);
}
