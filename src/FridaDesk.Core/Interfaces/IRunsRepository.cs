using FridaDesk.Core.Models;
using FridaDesk.Core.Results;

namespace FridaDesk.Core.Interfaces;

public interface IRunsRepository
{
    Task<Result<RunRecord>> GetAsync(Guid id);
    Task<Result<IEnumerable<RunRecord>>> SearchAsync(string query);
    Task<Result> AddAsync(RunRecord record);
    Task<Result> UpdateAsync(RunRecord record);
    Task<Result> DeleteAsync(Guid id);
}
