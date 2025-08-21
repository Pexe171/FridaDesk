using FridaHub.Core.Interfaces;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace FridaHub.Infrastructure;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddFridaHubInfrastructure(this IServiceCollection services)
    {
        var folder = Paths.GetDataFolder();
        Directory.CreateDirectory(folder);
        var dbPath = Path.Combine(folder, "FridaHub.db");

        services.AddDbContext<FridaHubDbContext>(o => o.UseSqlite($"Data Source={dbPath}"));
        services.AddScoped<IScriptsRepository, EfScriptsRepository>();
        services.AddScoped<IRunsRepository, EfRunsRepository>();
        services.AddScoped<IDevicesRepository, EfDevicesRepository>();
        services.AddSingleton<ISettingsService, JsonSettingsService>();

        using var provider = services.BuildServiceProvider();
        var db = provider.GetRequiredService<FridaHubDbContext>();
        db.Database.Migrate();

        return services;
    }
}

