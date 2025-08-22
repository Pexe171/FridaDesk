using FridaHub.Core.Interfaces;
using FridaHub.Infrastructure.Repositories;
using FridaHub.Infrastructure.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace FridaHub.Infrastructure;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddFridaHubInfrastructure(this IServiceCollection services)
    {
        var baseDir = OperatingSystem.IsWindows()
            ? Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)
            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".local", "share");
        var appDir = Path.Combine(baseDir, "FridaHub");
        Directory.CreateDirectory(appDir);
        var dbPath = Path.Combine(appDir, "FridaHub.db");

        services.AddDbContext<FridaHubDbContext>(options =>
            options.UseSqlite($"Data Source={dbPath}"));

        services.AddScoped<IScriptsRepository, EfScriptsRepository>();
        services.AddScoped<IRunsRepository, EfRunsRepository>();
        services.AddScoped<IDevicesRepository, EfDevicesRepository>();
        services.AddSingleton<ISettingsService, JsonSettingsService>();
        services.AddSingleton<IDiagnosticsService, DiagnosticsService>();

        return services;
    }
}
