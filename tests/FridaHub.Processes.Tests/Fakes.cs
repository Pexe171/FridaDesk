using FridaHub.Core.Interfaces;
using FridaHub.Core.Models;
using FridaHub.Core.Results;

namespace FridaHub.Processes.Tests;

class FakeSettingsService : ISettingsService
{
    public Settings? Current { get; private set; } = new();
    public Task<Result<Settings>> LoadAsync() => Task.FromResult(Result<Settings>.Success(new Settings()));
    public Task<Result> SaveAsync(Settings settings)
    {
        Current = settings;
        return Task.FromResult(Result.Success());
    }
}
