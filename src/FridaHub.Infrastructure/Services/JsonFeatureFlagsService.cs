using System.Text.Json;
using FridaHub.Core.Interfaces;
using FridaHub.Core.Models;
using FridaHub.Core.Results;

namespace FridaHub.Infrastructure.Services;

public class JsonFeatureFlagsService : IFeatureFlagsService
{
    private readonly string _filePath;
    public FeatureFlags? Current { get; private set; }

    public JsonFeatureFlagsService(string? filePath = null)
    {
        if (string.IsNullOrWhiteSpace(filePath))
        {
            var baseDir = OperatingSystem.IsWindows()
                ? Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)
                : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".local", "share");
            var appDir = Path.Combine(baseDir, "FridaHub");
            Directory.CreateDirectory(appDir);
            _filePath = Path.Combine(appDir, "featureflags.json");
        }
        else
        {
            _filePath = filePath;
            var dir = Path.GetDirectoryName(_filePath)!;
            Directory.CreateDirectory(dir);
        }
    }

    public async Task<Result<FeatureFlags>> LoadAsync()
    {
        try
        {
            if (!File.Exists(_filePath))
            {
                Current = new FeatureFlags();
                return Result<FeatureFlags>.Success(Current);
            }

            await using var stream = File.OpenRead(_filePath);
            var flags = await JsonSerializer.DeserializeAsync<FeatureFlags>(stream) ?? new FeatureFlags();
            Current = flags;
            return Result<FeatureFlags>.Success(flags);
        }
        catch (Exception ex)
        {
            return Result<FeatureFlags>.Failure(ex.Message);
        }
    }

    public async Task<Result> SaveAsync(FeatureFlags flags)
    {
        try
        {
            var dir = Path.GetDirectoryName(_filePath)!;
            Directory.CreateDirectory(dir);
            await using var stream = File.Create(_filePath);
            await JsonSerializer.SerializeAsync(stream, flags, new JsonSerializerOptions { WriteIndented = true });
            Current = flags;
            return Result.Success();
        }
        catch (Exception ex)
        {
            return Result.Failure(ex.Message);
        }
    }
}
