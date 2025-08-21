using System.Text.Json;
using FridaHub.Core.Interfaces;
using FridaHub.Core.Models;
using FridaHub.Core.Results;

namespace FridaHub.Infrastructure;

public class JsonSettingsService : ISettingsService
{
    private readonly string _settingsPath;
    private Settings? _current;

    public JsonSettingsService()
    {
        var folder = Paths.GetDataFolder();
        Directory.CreateDirectory(folder);
        _settingsPath = Path.Combine(folder, "settings.json");
    }

    public Settings? Current => _current;

    public async Task<Result<Settings>> LoadAsync()
    {
        try
        {
            if (File.Exists(_settingsPath))
            {
                await using var stream = File.OpenRead(_settingsPath);
                _current = await JsonSerializer.DeserializeAsync<Settings>(stream) ?? new Settings();
            }
            else
            {
                _current = new Settings();
            }

            return Result<Settings>.Success(_current);
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
            await using var stream = File.Create(_settingsPath);
            await JsonSerializer.SerializeAsync(stream, settings, new JsonSerializerOptions { WriteIndented = true });
            _current = settings;
            return Result.Success();
        }
        catch (Exception ex)
        {
            return Result.Failure(ex.Message);
        }
    }
}

