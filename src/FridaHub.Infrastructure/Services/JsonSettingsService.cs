using System.Text.Json;
using FridaHub.Core.Interfaces;
using FridaHub.Core.Models;
using FridaHub.Core.Results;

namespace FridaHub.Infrastructure.Services;

public class JsonSettingsService : ISettingsService
{
    private readonly string _filePath;
    public Settings? Current { get; private set; }

    public JsonSettingsService()
    {
        var baseDir = OperatingSystem.IsWindows()
            ? Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)
            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".local", "share");
        var appDir = Path.Combine(baseDir, "FridaHub");
        Directory.CreateDirectory(appDir);
        _filePath = Path.Combine(appDir, "settings.json");
    }

    public async Task<Result<Settings>> LoadAsync()
    {
        try
        {
            if (!File.Exists(_filePath))
            {
                Current = new Settings { EnableJailbreakFeature = false };
                return Result<Settings>.Success(Current);
            }

            await using var stream = File.OpenRead(_filePath);
            var settings = await JsonSerializer.DeserializeAsync<Settings>(stream) ?? new Settings();
            Current = settings;
            return Result<Settings>.Success(settings);
        }
        catch (Exception ex)
        {
            return Result<Settings>.Failure(ex.Message);
        }
    }

    public async Task<Result> SaveAsync(Settings settings)
    {
        try
        {
            var dir = Path.GetDirectoryName(_filePath)!;
            Directory.CreateDirectory(dir);
            await using var stream = File.Create(_filePath);
            await JsonSerializer.SerializeAsync(stream, settings, new JsonSerializerOptions { WriteIndented = true });
            Current = settings;
            return Result.Success();
        }
        catch (Exception ex)
        {
            return Result.Failure(ex.Message);
        }
    }
}
