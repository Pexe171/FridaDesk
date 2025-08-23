using FridaHub.Core.Models;
using FridaHub.Core.Results;

namespace FridaHub.Core.Interfaces;

public interface IFeatureFlagsService
{
    FeatureFlags? Current { get; }
    Task<Result<FeatureFlags>> LoadAsync();
    Task<Result> SaveAsync(FeatureFlags flags);
}
