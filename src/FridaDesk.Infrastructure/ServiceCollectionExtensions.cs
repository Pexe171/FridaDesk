using FridaDesk.Core.Interfaces;
using FridaDesk.Infrastructure.Repositories;
using FridaDesk.Infrastructure.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace FridaDesk.Infrastructure;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddFridaDeskInfrastructure(this IServiceCollection services)
    {
        var baseDir = OperatingSystem.IsWindows()
            ? Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)
            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".local", "share");
        var appDir = Path.Combine(baseDir, "FridaDesk");
        Directory.CreateDirectory(appDir);
        var dbPath = Path.Combine(appDir, "FridaDesk.db");

        services.AddDbContext<FridaDeskDbContext>(options =>
            options.UseSqlite($"Data Source={dbPath}"));

        // Ensure database created
        using (var db = new FridaDeskDbContext(new DbContextOptionsBuilder<FridaDeskDbContext>().UseSqlite($"Data Source={dbPath}").Options))
        {
            db.Database.EnsureCreated();
        }

        services.AddScoped<IScriptsRepository, EfScriptsRepository>();
        services.AddScoped<IRunsRepository, EfRunsRepository>();
        services.AddScoped<IDevicesRepository, EfDevicesRepository>();
        services.AddSingleton<ISettingsService, JsonSettingsService>();

        return services;
    }
}
