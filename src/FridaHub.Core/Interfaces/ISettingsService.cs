using FridaHub.Core.Models;
using FridaHub.Core.Results;

namespace FridaHub.Core.Interfaces;

public interface ISettingsService
{
    Task<Result<Settings>> LoadAsync();
    Task<Result> SaveAsync(Settings settings);
    Settings? Current { get; }
}
