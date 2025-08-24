using FridaDesk.Core.Models;
using FridaDesk.Core.Results;

namespace FridaDesk.Core.Interfaces;

public interface ISettingsService
{
    Task<Result<Settings>> LoadAsync();
    Task<Result> SaveAsync(Settings settings);
    Settings? Current { get; }
}
