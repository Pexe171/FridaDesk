using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.EntityFrameworkCore;
using FridaHub.Infrastructure;
using FridaHub.Processes;
using FridaHub.Core.Backends;
using FridaHub.App.ViewModels;
using FridaHub.App.Views;
using FridaHub.Codeshare;
using FridaHub.Core.Interfaces;

namespace FridaHub.App;

public static class ServiceConfigurator
{
    public static IServiceProvider Configure()
    {
        var services = new ServiceCollection();

        services.AddFridaHubInfrastructure();
        services.AddScoped<CodeshareSeedLoader>();
        services.AddSingleton<ProcessRunner>();
        services.AddSingleton<IAdbBackend, AdbService>();
        services.AddSingleton<IFridaBackend, CliFridaBackend>();
        services.AddSingleton<IFridaVersionChecker, FridaVersionChecker>();
        services.AddSingleton<IFridaInstaller, FridaInstaller>();

        services.AddSingleton<MainViewModel>();
        services.AddSingleton<DevicesViewModel>();
        services.AddSingleton<ScriptsViewModel>();
        services.AddSingleton<RunViewModel>();
        services.AddSingleton<HistoryViewModel>();
        services.AddSingleton<SettingsViewModel>();
        services.AddSingleton<DiagnosticsViewModel>();

        services.AddTransient<MainView>();
        services.AddTransient<DevicesView>();
        services.AddTransient<ScriptsView>();
        services.AddTransient<RunView>();
        services.AddTransient<HistoryView>();
        services.AddTransient<SettingsView>();
        services.AddTransient<DiagnosticsView>();

        var provider = services.BuildServiceProvider();

        using (var scope = provider.CreateScope())
        {
            var context = scope.ServiceProvider.GetRequiredService<FridaHubDbContext>();
            context.Database.Migrate();

            var seeder = scope.ServiceProvider.GetRequiredService<CodeshareSeedLoader>();
            seeder.LoadAsync().GetAwaiter().GetResult();
        }

        return provider;
    }
}
